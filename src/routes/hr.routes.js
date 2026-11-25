const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const XLSX = require('xlsx');
const {
  User,
  Application,
  Campaign,
  LeaveRequest,
  Department,
  Task,
  AuditLog,
  Notification,
  Announcement,
} = require('../models');
const { sendNotification } = require('../services/notification.service');
const {
  protect,
  authorize,
  requireDepartmentScope,
  requireHRRecruitmentManage,
  requireHRExport,
  requireHRCoordinationIncharge,
  requireAccountCreateAuthority,
  ALLOWED_ROLES,
  getMemoryUsersList,
  setMemoryUser,
} = require('../middleware/auth');
const { validateRoleDesignation, normalizeDesignation, hasCapability, CAPABILITIES } = require('../constants/roles');

function escapeCsv(val) {
  let str = String(val ?? '');
  if (/^[=+\-@\t\r]/.test(str)) {
    str = "'" + str;
  }
  if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

// ---------------------------------------------------------------------------
// In-Memory Storage Fallback for Controlled Configuration Mode
// ---------------------------------------------------------------------------
const memoryCampaigns = new Map();
const memoryApplications = new Map();
const memoryLeaves = new Map();
const memoryAnnouncements = new Map();

function setMemoryCampaign(campaign) {
  const id = campaign._id ? campaign._id.toString() : campaign.id;
  memoryCampaigns.set(id, campaign);
}

function getMemoryCampaignsList() {
  return Array.from(memoryCampaigns.values());
}

function setMemoryApplication(app) {
  const id = app._id ? app._id.toString() : app.id;
  memoryApplications.set(id, app);
}

function getMemoryApplicationsList() {
  return Array.from(memoryApplications.values());
}

function setMemoryLeave(leave) {
  const id = leave._id ? leave._id.toString() : leave.id;
  memoryLeaves.set(id, leave);
}

function getMemoryLeavesList() {
  return Array.from(memoryLeaves.values());
}

function setMemoryAnnouncement(ann) {
  const id = ann._id ? ann._id.toString() : ann.id || ann.announcementId;
  memoryAnnouncements.set(id, ann);
}

function getMemoryAnnouncementsList() {
  return Array.from(memoryAnnouncements.values());
}

// Department mapping
const DEPT_ROLE_MAP = {
  dept_literature: { name: 'Literature', code: 'LIT' },
  dept_media: { name: 'Media', code: 'MED' },
  dept_marketing: { name: 'Marketing', code: 'MKT' },
  dept_outreach: { name: 'Outreach', code: 'OUT' },
  dept_content: { name: 'Content Creation', code: 'CON' },
  hr: { name: 'HR', code: 'HR' },
  finance: { name: 'Finance', code: 'FIN' },
};

const VALID_DEPARTMENTS = [
  'Literature',
  'Media',
  'Marketing',
  'Outreach',
  'Content Creation',
  'HR',
  'Finance',
];

// Memory campaigns initialize strictly empty in production zero-state

// ---------------------------------------------------------------------------
// 1. RECRUITMENT CAMPAIGNS
// ---------------------------------------------------------------------------

/**
 * @route   GET /api/hr/campaigns
 * @desc    List all recruitment campaigns
 * @access  Protected (All authenticated staff & members)
 */
router.get('/campaigns', protect, async (req, res) => {
  try {
    const { status, department } = req.query;
    let campaigns = [];
    try {
      const filter = {};
      if (status) filter.status = status;
      if (department) filter.department = department;
      campaigns = await Campaign.find(filter).sort({ createdAt: -1 });
    } catch {}

    if (!campaigns || campaigns.length === 0) {
      campaigns = getMemoryCampaignsList();
      if (status) campaigns = campaigns.filter((c) => c.status === status);
      if (department) campaigns = campaigns.filter((c) => c.department === department);
    }

    return res.json({ success: true, count: campaigns.length, campaigns });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to fetch campaigns.' });
  }
});

/**
 * @route   POST /api/hr/campaigns
 * @desc    Create a new recruitment campaign
 * @access  Protected (Super Admin, HR Head, HR Director, HR In-charge)
 */
router.post('/campaigns', protect, requireHRRecruitmentManage, async (req, res) => {
  try {
    const { title, department, description, requirements, openingsCount, deadline, status } = req.body;

    if (!title || !description) {
      return res.status(400).json({
        success: false,
        error: 'Campaign title and description are required.',
      });
    }

    const campaignDept = department || 'General';
    if (campaignDept !== 'General' && !VALID_DEPARTMENTS.includes(campaignDept)) {
      return res.status(400).json({
        success: false,
        error: `Invalid department '${campaignDept}'. Valid options: General, ${VALID_DEPARTMENTS.join(', ')}.`,
      });
    }

    let campaign = null;
    try {
      campaign = await Campaign.create({
        title,
        department: campaignDept,
        description,
        requirements: Array.isArray(requirements) ? requirements : requirements ? [requirements] : [],
        openingsCount: openingsCount ? parseInt(openingsCount, 10) : 1,
        deadline: deadline ? new Date(deadline) : undefined,
        status: status || 'active',
        createdBy: req.user.id || req.user._id,
        createdByName: req.user.name,
      });
    } catch {
      const campId = `camp_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
      campaign = {
        _id: campId,
        id: campId,
        title,
        department: campaignDept,
        description,
        requirements: Array.isArray(requirements) ? requirements : requirements ? [requirements] : [],
        openingsCount: openingsCount ? parseInt(openingsCount, 10) : 1,
        deadline: deadline ? new Date(deadline) : undefined,
        status: status || 'active',
        createdBy: req.user.id || req.user._id,
        createdByName: req.user.name,
        applicationsCount: 0,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      setMemoryCampaign(campaign);
    }

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'RECRUITMENT_CAMPAIGN_CREATED',
      module: 'HR_MANAGEMENT',
      targetId: campaign._id?.toString() || campaign.id,
      targetModel: 'Campaign',
      description: `${req.user.name} created recruitment campaign: '${title}' (${campaignDept}).`,
    }).catch(() => null);

    return res.status(201).json({
      success: true,
      message: 'Recruitment campaign created successfully.',
      campaign,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to create recruitment campaign.' });
  }
});

/**
 * @route   GET /api/hr/campaigns/:id
 * @desc    Get single campaign details
 * @access  Protected (All authenticated staff & members)
 */
router.get('/campaigns/:id', protect, async (req, res) => {
  try {
    const { id } = req.params;
    let campaign = null;
    try {
      campaign = await Campaign.findById(id);
    } catch {}
    if (!campaign) campaign = memoryCampaigns.get(id);

    if (!campaign) {
      return res.status(404).json({ success: false, error: 'Campaign not found.' });
    }

    return res.json({ success: true, campaign });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to fetch campaign.' });
  }
});

/**
 * @route   PATCH /api/hr/campaigns/:id
 * @desc    Update campaign details or status
 * @access  Protected (Super Admin, HR Head, HR Director, HR In-charge)
 */
router.patch('/campaigns/:id', protect, requireHRRecruitmentManage, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, department, description, requirements, openingsCount, deadline, status } = req.body;

    let campaign = null;
    try {
      campaign = await Campaign.findById(id);
    } catch {}
    if (!campaign) campaign = memoryCampaigns.get(id);

    if (!campaign) {
      return res.status(404).json({ success: false, error: 'Campaign not found.' });
    }

    if (title) campaign.title = title;
    if (department) campaign.department = department;
    if (description) campaign.description = description;
    if (requirements) campaign.requirements = Array.isArray(requirements) ? requirements : [requirements];
    if (openingsCount) campaign.openingsCount = parseInt(openingsCount, 10);
    if (deadline) campaign.deadline = new Date(deadline);
    if (status) campaign.status = status;
    campaign.updatedAt = new Date();

    try {
      if (campaign.save) await campaign.save();
      else setMemoryCampaign(campaign);
    } catch {
      setMemoryCampaign(campaign);
    }

    return res.json({ success: true, message: 'Campaign updated successfully.', campaign });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to update campaign.' });
  }
});

/**
 * @route   DELETE /api/hr/campaigns/:id
 * @desc    Close or remove campaign
 * @access  Protected (Super Admin, HR Head, HR Director, HR In-charge)
 */
router.delete('/campaigns/:id', protect, requireHRRecruitmentManage, async (req, res) => {
  try {
    const { id } = req.params;
    let campaign = null;
    try {
      campaign = await Campaign.findById(id);
    } catch {}
    if (!campaign) campaign = memoryCampaigns.get(id);

    if (!campaign) {
      return res.status(404).json({ success: false, error: 'Campaign not found.' });
    }

    campaign.status = 'closed';
    campaign.updatedAt = new Date();

    try {
      if (campaign.save) await campaign.save();
      else setMemoryCampaign(campaign);
    } catch {
      setMemoryCampaign(campaign);
    }

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'RECRUITMENT_CAMPAIGN_CLOSED',
      module: 'HR_MANAGEMENT',
      targetId: id,
      targetModel: 'Campaign',
      description: `${req.user.name} closed recruitment campaign: '${campaign.title}'.`,
    }).catch(() => null);

    return res.json({ success: true, message: 'Campaign closed successfully.', campaign });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to close campaign.' });
  }
});

// ---------------------------------------------------------------------------
// 2. CANDIDATE APPLICATIONS & RECRUITMENT LIFECYCLE
// ---------------------------------------------------------------------------

/**
 * @route   GET /api/hr/applications
 * @desc    List candidate applications with filters
 * @access  Protected (Super Admin & HR Only)
 */
router.get('/applications', protect, authorize('super_admin', 'hr'), async (req, res) => {
  try {
    const { status, department, source, search } = req.query;
    let applications = [];
    try {
      const filter = {};
      if (status && status !== 'all') filter.status = status;
      if (department && department !== 'all') {
        filter.$or = [{ department }, { areaOfInterest: { $regex: department, $options: 'i' } }];
      }
      if (source && source !== 'all') filter.source = source;
      if (search) {
        filter.$or = [
          { fullName: { $regex: search, $options: 'i' } },
          { email: { $regex: search, $options: 'i' } },
          { phoneNumber: { $regex: search, $options: 'i' } },
        ];
      }
      applications = await Application.find(filter).sort({ createdAt: -1 });
    } catch {}

    if (!applications || applications.length === 0) {
      applications = getMemoryApplicationsList();
      if (status && status !== 'all') applications = applications.filter((a) => a.status === status);
      if (department && department !== 'all') {
        const d = department.toLowerCase();
        applications = applications.filter(
          (a) => a.department?.toLowerCase() === d || a.areaOfInterest?.toLowerCase().includes(d)
        );
      }
      if (source && source !== 'all') applications = applications.filter((a) => a.source === source);
      if (search) {
        const s = search.toLowerCase();
        applications = applications.filter(
          (a) =>
            a.fullName?.toLowerCase().includes(s) ||
            a.email?.toLowerCase().includes(s) ||
            a.phoneNumber?.includes(s)
        );
      }
    }

    return res.json({ success: true, count: applications.length, applications });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to fetch applications.' });
  }
});

/**
 * @route   GET /api/hr/applications/:id
 * @desc    Get single application record
 * @access  Protected (Super Admin & HR Only)
 */
router.get('/applications/:id', protect, authorize('super_admin', 'hr'), async (req, res) => {
  try {
    const { id } = req.params;
    let application = null;
    try {
      application = await Application.findById(id);
    } catch {}
    if (!application) application = memoryApplications.get(id);

    if (!application) {
      return res.status(404).json({ success: false, error: 'Application record not found.' });
    }

    return res.json({ success: true, application });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to fetch application.' });
  }
});

/**
 * @route   PATCH /api/hr/applications/:id/status
 * @desc    Update application review status
 * @access  Protected (Super Admin, HR Head, HR Director, HR In-charge)
 */
router.patch('/applications/:id/status', protect, requireHRRecruitmentManage, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, notes } = req.body;

    const validStatuses = [
      'submitted',
      'pending',
      'under_review',
      'shortlisted',
      'interview_scheduled',
      'interview_completed',
      'selected',
      'not_selected',
      'rejected',
    ];
    if (!status || !validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        error: `Invalid status. Valid values: ${validStatuses.join(', ')}.`,
      });
    }

    let application = null;
    try {
      application = await Application.findById(id);
    } catch {}
    if (!application) application = memoryApplications.get(id);

    if (!application) {
      return res.status(404).json({ success: false, error: 'Application record not found.' });
    }

    application.status = status;
    application.reviewNotes = notes || application.reviewNotes;
    application.reviewedBy = req.user.id || req.user._id;
    application.reviewedAt = new Date();

    if (!application.statusHistory) application.statusHistory = [];
    application.statusHistory.push({
      status,
      changedBy: req.user.id || req.user._id,
      changedByName: req.user.name,
      changedAt: new Date(),
      note: notes || `Application moved to ${status}.`,
    });

    try {
      if (application.save) await application.save();
      else setMemoryApplication(application);
    } catch {
      setMemoryApplication(application);
    }

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'RECRUITMENT_APPLICATION_STATUS_UPDATED',
      module: 'HR_MANAGEMENT',
      targetId: id,
      targetModel: 'Application',
      description: `${req.user.name} changed application status for ${application.fullName} to '${status}'.`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: `Application status updated to ${status}.`,
      application,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to update application status.' });
  }
});

/**
 * @route   POST /api/hr/applications/:id/assign-interviewer
 * @desc    Assign interviewer to candidate application
 * @access  Protected (Super Admin, HR Head, HR Director, HR In-charge)
 */
router.post('/applications/:id/assign-interviewer', protect, requireHRRecruitmentManage, async (req, res) => {
  try {
    const { id } = req.params;
    const { interviewerId, interviewerName, scheduledAt, mode, meetingLink, notes } = req.body;

    if (!interviewerId) {
      return res.status(400).json({ success: false, error: 'Interviewer ID is required.' });
    }

    let application = null;
    try {
      application = await Application.findById(id);
    } catch {}
    if (!application) application = memoryApplications.get(id);

    if (!application) {
      return res.status(404).json({ success: false, error: 'Application record not found.' });
    }

    application.assignedInterviewer = interviewerId;
    application.status = 'interview_scheduled';
    application.interviewDetails = {
      ...(application.interviewDetails || {}),
      interviewerId,
      interviewerName: interviewerName || 'Assigned Interviewer',
      scheduledAt: scheduledAt ? new Date(scheduledAt) : new Date(Date.now() + 2 * 24 * 60 * 60 * 1000),
      mode: mode || 'Online',
      meetingLink: meetingLink || '',
      notes: notes || '',
    };

    if (!application.statusHistory) application.statusHistory = [];
    application.statusHistory.push({
      status: 'interview_scheduled',
      changedBy: req.user.id || req.user._id,
      changedByName: req.user.name,
      changedAt: new Date(),
      note: `Interviewer assigned: ${interviewerName || interviewerId}.`,
    });

    try {
      if (application.save) await application.save();
      else setMemoryApplication(application);
    } catch {
      setMemoryApplication(application);
    }

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'RECRUITMENT_INTERVIEWER_ASSIGNED',
      module: 'HR_MANAGEMENT',
      targetId: id,
      targetModel: 'Application',
      description: `${req.user.name} assigned interviewer (${interviewerName || interviewerId}) for candidate ${application.fullName}.`,
    }).catch(() => null);

    // Notify assigned interviewer
    await sendNotification({
      userId: interviewerId,
      title: 'Interview Assigned',
      message: `You have been assigned to conduct an interview with ${application.fullName} (${application.department || application.areaOfInterest || 'Applicant'}).`,
      type: 'info',
      category: 'recruitment',
      link: `/portal/hr?tab=recruitment&appId=${id}`,
      dedupKey: `interview:assign:${id}:${interviewerId}`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: `Interviewer successfully assigned for ${application.fullName}.`,
      application,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to assign interviewer.' });
  }
});

/**
 * @route   POST /api/hr/applications/:id/interview-feedback
 * @desc    Submit interview feedback and recommendation
 * @access  Protected (Assigned Interviewer, Super Admin, HR Leadership)
 */
router.post('/applications/:id/interview-feedback', protect, async (req, res) => {
  try {
    const { id } = req.params;
    const { rating, recommendation, feedbackNotes } = req.body;

    const validRecommendations = ['hire', 'reject', 'on_hold', 'strong_hire'];
    if (!recommendation || !validRecommendations.includes(recommendation)) {
      return res.status(400).json({
        success: false,
        error: `Valid recommendation required: ${validRecommendations.join(', ')}.`,
      });
    }

    let application = null;
    try {
      application = await Application.findById(id);
    } catch {}
    if (!application) application = memoryApplications.get(id);

    if (!application) {
      return res.status(404).json({ success: false, error: 'Application record not found.' });
    }

    const currentUserId = (req.user.id || req.user._id)?.toString();
    const isAssignedInterviewer =
      application.assignedInterviewer?.toString() === currentUserId ||
      application.interviewDetails?.interviewerId?.toString() === currentUserId ||
      (Array.isArray(application.interviewDetails?.interviewers) &&
        application.interviewDetails.interviewers.includes(req.user.name));
    const hasHRManage = hasCapability(req.user, CAPABILITIES.HR_RECRUITMENT_MANAGE);
    const isSuperAdmin = req.user.role === 'super_admin';

    if (!isAssignedInterviewer && !hasHRManage && !isSuperAdmin) {
      return res.status(403).json({
        success: false,
        error: 'Forbidden: Only the assigned interviewer or HR leadership can submit interview feedback.',
      });
    }

    if (!application.interviewDetails) application.interviewDetails = {};
    application.interviewDetails.rating = rating !== undefined ? Number(rating) : undefined;
    application.interviewDetails.recommendation = recommendation;
    application.interviewDetails.feedback = feedbackNotes || '';
    application.interviewDetails.submittedAt = new Date();
    application.interviewDetails.interviewerId = currentUserId;
    application.interviewDetails.interviewerName = req.user.name;

    // Note: Feedback submission records recommendation, but does NOT finalize recruitment decision
    application.status = 'interview_completed';

    if (!application.statusHistory) application.statusHistory = [];
    application.statusHistory.push({
      status: 'interview_completed',
      changedBy: currentUserId,
      changedByName: req.user.name,
      changedAt: new Date(),
      note: `Interview feedback submitted: Recommendation='${recommendation}'${rating ? `, Rating=${rating}/5` : ''}.`,
    });

    try {
      if (application.save) await application.save();
      else setMemoryApplication(application);
    } catch {
      setMemoryApplication(application);
    }

    await AuditLog.create({
      actorId: currentUserId,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'RECRUITMENT_INTERVIEW_FEEDBACK_SUBMITTED',
      module: 'HR_MANAGEMENT',
      targetId: id,
      targetModel: 'Application',
      description: `${req.user.name} submitted interview recommendation '${recommendation}' for candidate ${application.fullName}.`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: 'Interview feedback recorded successfully.',
      application,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to record interview feedback.' });
  }
});

/**
 * @route   POST /api/hr/applications/:id/decision
 * @desc    Record final recruitment decision (selected, not_selected, rejected)
 * @access  Protected (Super Admin, HR Head, HR Director, HR In-charge)
 */
router.post('/applications/:id/decision', protect, requireHRRecruitmentManage, async (req, res) => {
  try {
    const { id } = req.params;
    const { decision, notes } = req.body;

    const validDecisions = ['selected', 'not_selected', 'rejected'];
    if (!decision || !validDecisions.includes(decision)) {
      return res.status(400).json({
        success: false,
        error: `Valid decision required: ${validDecisions.join(', ')}.`,
      });
    }

    let application = null;
    try {
      application = await Application.findById(id);
    } catch {}
    if (!application) application = memoryApplications.get(id);

    if (!application) {
      return res.status(404).json({ success: false, error: 'Application record not found.' });
    }

    const currentUserId = (req.user.id || req.user._id)?.toString();
    application.status = decision;
    application.decisionDetails = {
      decision,
      decidedBy: currentUserId,
      decidedByName: req.user.name,
      decidedByRole: req.user.role,
      decidedByDesignation: req.user.designation || '',
      decidedAt: new Date(),
      decisionNotes: notes || '',
    };

    if (!application.statusHistory) application.statusHistory = [];
    application.statusHistory.push({
      status: decision,
      changedBy: currentUserId,
      changedByName: req.user.name,
      changedAt: new Date(),
      note: `Final recruitment decision: '${decision}'. Notes: ${notes || 'None'}.`,
    });

    try {
      if (application.save) await application.save();
      else setMemoryApplication(application);
    } catch {
      setMemoryApplication(application);
    }

    await AuditLog.create({
      actorId: currentUserId,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'RECRUITMENT_FINAL_DECISION_RECORDED',
      module: 'HR_MANAGEMENT',
      targetId: id,
      targetModel: 'Application',
      description: `${req.user.name} recorded final recruitment decision '${decision}' for candidate ${application.fullName}.`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: `Candidate application marked as ${decision}.`,
      application,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to record final decision.' });
  }
});

/**
 * @route   POST /api/hr/applications/:id/interview
 * @desc    Schedule candidate interview
 * @access  Protected (Super Admin, HR Head, HR Director, HR In-charge)
 */
router.post('/applications/:id/interview', protect, requireHRRecruitmentManage, async (req, res) => {
  try {
    const { id } = req.params;
    const { scheduledAt, interviewers, mode, meetingLink, notes } = req.body;

    if (!scheduledAt) {
      return res.status(400).json({ success: false, error: 'Interview schedule date and time are required.' });
    }

    let application = null;
    try {
      application = await Application.findById(id);
    } catch {}
    if (!application) application = memoryApplications.get(id);

    if (!application) {
      return res.status(404).json({ success: false, error: 'Application not found.' });
    }

    application.status = 'interview_scheduled';
    application.interviewDetails = {
      ...(application.interviewDetails || {}),
      scheduledAt: new Date(scheduledAt),
      interviewers: Array.isArray(interviewers) ? interviewers : interviewers ? [interviewers] : [req.user.name],
      mode: mode || 'Online',
      meetingLink: meetingLink || '',
      notes: notes || '',
    };

    if (!application.statusHistory) application.statusHistory = [];
    application.statusHistory.push({
      status: 'interview_scheduled',
      changedBy: req.user.id || req.user._id,
      changedByName: req.user.name,
      changedAt: new Date(),
      note: `Interview scheduled for ${new Date(scheduledAt).toLocaleString()}${notes ? ': ' + notes : ''}.`,
    });

    try {
      if (application.save) await application.save();
      else setMemoryApplication(application);
    } catch {
      setMemoryApplication(application);
    }

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'RECRUITMENT_INTERVIEW_SCHEDULED',
      module: 'HR_MANAGEMENT',
      targetId: id,
      targetModel: 'Application',
      description: `${req.user.name} scheduled interview for candidate ${application.fullName} on ${new Date(scheduledAt).toLocaleDateString()}.`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: `Interview scheduled successfully for ${application.fullName}.`,
      application,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to schedule interview.' });
  }
});

/**
 * @route   POST /api/hr/applications/:id/onboard
 * @desc    Select candidate and onboard as a staff / team member
 * @access  Protected (Super Admin, HR Head, HR Director, HR In-charge)
 */
router.post('/applications/:id/onboard', protect, requireHRRecruitmentManage, async (req, res) => {
  try {
    const { id } = req.params;
    const { role, department, designation } = req.body;

    const assignedRole = role || 'member';
    if (!ALLOWED_ROLES.includes(assignedRole)) {
      return res.status(400).json({
        success: false,
        error: `Invalid role '${assignedRole}'. Must be one of: ${ALLOWED_ROLES.join(', ')}.`,
      });
    }

    // Role escalation prevention: HR cannot create Super Admin
    if (assignedRole === 'super_admin' && req.user.role !== 'super_admin') {
      return res.status(403).json({
        success: false,
        error: 'Forbidden: Only Super Admin can onboard users into the super_admin role.',
      });
    }

    let application = null;
    try {
      application = await Application.findById(id);
    } catch {}
    if (!application) application = memoryApplications.get(id);

    if (!application) {
      return res.status(404).json({ success: false, error: 'Application not found.' });
    }

    // Duplicate onboarding prevention: Check if candidate was already onboarded
    if (application.status === 'selected' || application.onboardingDetails?.userId) {
      return res.status(400).json({
        success: false,
        error: 'Duplicate onboarding rejected: Candidate has already been onboarded.',
      });
    }

    // Check if user account already exists in DB or memory
    let existingUser = null;
    try {
      existingUser = await User.findOne({ email: application.email.toLowerCase().trim() });
    } catch {}
    if (!existingUser) {
      existingUser = getMemoryUsersList().find((u) => u.email === application.email.toLowerCase().trim());
    }
    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: `User account with email '${application.email}' already exists.`,
      });
    }

    const assignedDept = department || application.department || 'Literature';
    if (!VALID_DEPARTMENTS.includes(assignedDept)) {
      return res.status(400).json({
        success: false,
        error: `Invalid department '${assignedDept}'.`,
      });
    }

    // Generate activation token
    const rawActivationToken = crypto.randomBytes(32).toString('hex');
    const hashedActivationToken = crypto.createHash('sha256').update(rawActivationToken).digest('hex');
    const activationExpires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

    // Validate role-designation compatibility
    let resolvedDesignation = 'member';
    if (designation) {
      const validation = validateRoleDesignation(assignedRole, designation);
      if (!validation.valid) {
        return res.status(400).json({ success: false, error: validation.error });
      }
      // If caller is HR (not Super Admin), HR cannot appoint operational Department Heads or Directors, or HR Head
      if (req.user.role !== 'super_admin') {
        const normalized = validation.designation;
        if (['head', 'director'].includes(normalized) && assignedRole !== 'hr') {
          return res.status(403).json({
            success: false,
            error: 'Forbidden: Appointing operational Department Heads and Directors requires Super Admin authorization.',
          });
        }
        if (normalized === 'hr_head') {
          return res.status(403).json({
            success: false,
            error: 'Forbidden: Appointing an HR Head requires Super Admin authorization.',
          });
        }
      }
      resolvedDesignation = validation.designation || 'member';
    }

    // Temporary placeholder password (must be activated via link)
    const tempPasswordHash = await bcrypt.hash(crypto.randomBytes(16).toString('hex'), 12);

    let newUser = null;
    try {
      newUser = await User.create({
        name: application.fullName,
        email: application.email.toLowerCase().trim(),
        password: tempPasswordHash,
        role: assignedRole,
        department: assignedDept,
        departmentCode: DEPT_ROLE_MAP[assignedRole]?.code || 'LIT',
        designation: resolvedDesignation,
        phoneNumber: application.phoneNumber,
        status: 'inactive',
        activationToken: hashedActivationToken,
        activationExpires,
      });
    } catch (err) {
      const existingUser = getMemoryUsersList().find((u) => u.email === application.email.toLowerCase().trim());
      if (existingUser) {
        return res.status(400).json({
          success: false,
          error: `User account with email '${application.email}' already exists.`,
        });
      }
      const uId = `usr_onboard_${Date.now()}`;
      newUser = {
        _id: uId,
        id: uId,
        name: application.fullName,
        email: application.email.toLowerCase().trim(),
        password: tempPasswordHash,
        role: assignedRole,
        department: assignedDept,
        designation: resolvedDesignation,
        phoneNumber: application.phoneNumber,
        status: 'inactive',
        activationToken: hashedActivationToken,
        activationExpires,
        createdAt: new Date(),
      };
      setMemoryUser(newUser);
    }

    // Update application
    application.status = 'selected';
    application.onboardingDetails = {
      onboardedAt: new Date(),
      assignedRole,
      assignedDepartment: assignedDept,
      userId: newUser._id || newUser.id,
    };

    if (!application.statusHistory) application.statusHistory = [];
    application.statusHistory.push({
      status: 'selected',
      changedBy: req.user.id || req.user._id,
      changedByName: req.user.name,
      changedAt: new Date(),
      note: `Candidate selected and onboarded as '${assignedRole}' in '${assignedDept}'. Activation token generated.`,
    });

    try {
      if (application.save) await application.save();
      else setMemoryApplication(application);
    } catch {
      setMemoryApplication(application);
    }

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'RECRUITMENT_CANDIDATE_ONBOARDED',
      module: 'HR_MANAGEMENT',
      targetId: id,
      targetModel: 'Application',
      description: `${req.user.name} onboarded candidate ${application.fullName} into role '${assignedRole}' (${assignedDept}).`,
    }).catch(() => null);

    const hrRecipients = getMemoryUsersList().filter((u) => ['hr', 'super_admin'].includes(u.role));
    for (const hrUser of hrRecipients) {
      await sendNotification({
        userId: hrUser.id || hrUser._id,
        title: 'Candidate Onboarded',
        message: `${application.fullName} was onboarded into role '${assignedRole}' (${assignedDept}).`,
        type: 'success',
        category: 'recruitment',
        link: '/portal/hr?tab=employees',
        dedupKey: `candidate:onboard:${id}:${hrUser.id || hrUser._id}`,
      }).catch(() => null);
    }

    return res.status(201).json({
      success: true,
      message: `Candidate ${application.fullName} successfully onboarded.`,
      user: {
        id: newUser._id || newUser.id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
        department: newUser.department,
        status: newUser.status,
      },
      activationToken: rawActivationToken,
      activationUrl: `/portal/activate?token=${rawActivationToken}`,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to onboard candidate.' });
  }
});

// ---------------------------------------------------------------------------
// 3. EMPLOYEE / STAFF DIRECTORY
// ---------------------------------------------------------------------------

/**
 * @route   GET /api/hr/employees
 * @desc    List all organization employees and volunteers
 * @access  Protected (Super Admin & HR Only)
 */
router.get('/employees', protect, authorize('super_admin', 'hr'), async (req, res) => {
  try {
    const { department, role, status, search } = req.query;
    let users = [];
    try {
      const filter = {};
      if (department && department !== 'all') filter.department = department;
      if (role && role !== 'all') filter.role = role;
      if (status && status !== 'all') filter.status = status;
      if (search) {
        filter.$or = [
          { name: { $regex: search, $options: 'i' } },
          { email: { $regex: search, $options: 'i' } },
        ];
      }
      users = await User.find(filter).select('-password').sort({ createdAt: -1 });
    } catch {}

    if (!users || users.length === 0) {
      users = getMemoryUsersList().map((u) => {
        const { password, refreshToken, ...safeUser } = u;
        return safeUser;
      });
      if (department && department !== 'all') users = users.filter((u) => u.department === department);
      if (role && role !== 'all') users = users.filter((u) => u.role === role);
      if (status && status !== 'all') users = users.filter((u) => u.status === status);
      if (search) {
        const s = search.toLowerCase();
        users = users.filter((u) => u.name?.toLowerCase().includes(s) || u.email?.toLowerCase().includes(s));
      }
    }

    return res.json({ success: true, count: users.length, employees: users });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to fetch employee directory.' });
  }
});

/**
 * @route   GET /api/hr/employees/:id
 * @desc    Get single employee profile, assigned tasks & leave history
 * @access  Protected (Super Admin, HR, or Self)
 */
router.get('/employees/:id', protect, async (req, res) => {
  try {
    const { id } = req.params;

    // Access check: only super_admin, hr, or the user themselves
    const isSelf = (req.user.id || req.user._id)?.toString() === id.toString();
    const isPrivileged = ['super_admin', 'hr'].includes(req.user.role);
    if (!isSelf && !isPrivileged) {
      return res.status(403).json({
        success: false,
        error: 'Forbidden: You do not have permission to view this employee record.',
      });
    }

    let user = null;
    try {
      user = await User.findById(id).select('-password');
    } catch {}
    if (!user) {
      const memUser = getMemoryUsersList().find((u) => (u._id || u.id)?.toString() === id.toString());
      if (memUser) {
        const { password, ...safe } = memUser;
        user = safe;
      }
    }

    if (!user) {
      return res.status(404).json({ success: false, error: 'Employee record not found.' });
    }

    // Active tasks summary
    let activeTasks = [];
    try {
      activeTasks = await Task.find({ assignedTo: id }).sort({ createdAt: -1 }).limit(10);
    } catch {}

    // Leave history
    let leaves = [];
    try {
      leaves = await LeaveRequest.find({ memberId: id }).sort({ createdAt: -1 });
    } catch {}

    return res.json({
      success: true,
      employee: user,
      activeTasks,
      leaveHistory: leaves,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to fetch employee details.' });
  }
});

/**
 * @route   PATCH /api/hr/employees/:id
 * @desc    Update employee information
 * @access  Protected (Super Admin & HR Only)
 */
router.patch('/employees/:id', protect, authorize('super_admin', 'hr'), async (req, res) => {
  try {
    const { id } = req.params;
    const { designation, department, phoneNumber, status } = req.body;

    let user = null;
    try {
      user = await User.findById(id);
    } catch {}
    if (!user) {
      user = getMemoryUsersList().find((u) => (u._id || u.id)?.toString() === id.toString());
    }

    if (!user) {
      return res.status(404).json({ success: false, error: 'Employee not found.' });
    }

    // Prevent changing Super Admin accounts if not super_admin
    if (user.role === 'super_admin' && req.user.role !== 'super_admin') {
      return res.status(403).json({
        success: false,
        error: 'Forbidden: HR cannot modify Super Admin records.',
      });
    }

    if (designation !== undefined) {
      // Validate role-designation compatibility
      const validation = validateRoleDesignation(user.role, designation);
      if (!validation.valid) {
        return res.status(400).json({ success: false, error: validation.error });
      }
      // If caller is HR (not Super Admin), HR cannot appoint Department Heads or Directors for operational departments, or HR Head
      if (req.user.role !== 'super_admin') {
        const normalized = validation.designation;
        if (['head', 'director'].includes(normalized) && user.role !== 'hr') {
          return res.status(403).json({
            success: false,
            error: 'Forbidden: Appointing operational Department Heads and Directors requires Super Admin authorization.',
          });
        }
        if (normalized === 'hr_head') {
          return res.status(403).json({
            success: false,
            error: 'Forbidden: Appointing an HR Head requires Super Admin authorization.',
          });
        }
      }
      user.designation = validation.designation;
    }
    if (phoneNumber !== undefined) user.phoneNumber = phoneNumber;
    if (status !== undefined && ['active', 'inactive', 'suspended'].includes(status)) {
      user.status = status;
    }
    if (department && VALID_DEPARTMENTS.includes(department)) {
      user.department = department;
    }

    try {
      if (user.save) await user.save();
      else setMemoryUser(user);
    } catch {
      setMemoryUser(user);
    }

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'HR_EMPLOYEE_UPDATED',
      module: 'HR_MANAGEMENT',
      targetId: id,
      targetModel: 'User',
      description: `${req.user.name} updated employee details for ${user.name}.`,
    }).catch(() => null);

    const { password, ...safeUser } = user;
    return res.json({ success: true, message: 'Employee record updated.', employee: safeUser });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to update employee.' });
  }
});

// ---------------------------------------------------------------------------
// 4. LEAVE MANAGEMENT LIFECYCLE
// ---------------------------------------------------------------------------

/**
 * @route   POST /api/hr/leaves
 * @desc    Submit a leave request
 * @access  Protected (All authenticated staff & members)
 */
router.post('/leaves', protect, async (req, res) => {
  try {
    const { leaveType, startDate, endDate, reason, supportingDoc } = req.body;

    if (!startDate || !endDate || !reason) {
      return res.status(400).json({
        success: false,
        error: 'Start date, end date, and reason are required to submit a leave request.',
      });
    }

    const start = new Date(startDate);
    const end = new Date(endDate);
    if (isNaN(start.getTime()) || isNaN(end.getTime()) || start > end) {
      return res.status(400).json({
        success: false,
        error: 'Invalid date range: Start date must precede or equal end date.',
      });
    }

    const validLeaveTypes = ['Sick', 'Exam', 'Personal', 'Emergency'];
    const chosenType = leaveType && validLeaveTypes.includes(leaveType) ? leaveType : 'Personal';

    const userDept = req.user.department || (req.user.role.startsWith('dept_') ? DEPT_ROLE_MAP[req.user.role]?.name : 'Literature') || 'Literature';

    let leaveRecord = null;
    try {
      leaveRecord = await LeaveRequest.create({
        memberId: req.user.id || req.user._id,
        memberName: req.user.name,
        memberEmail: req.user.email,
        department: userDept,
        leaveType: chosenType,
        startDate: start,
        endDate: end,
        reason: reason.trim(),
        supportingDoc: supportingDoc || '',
        status: 'pending',
        history: [
          {
            status: 'pending',
            changedBy: req.user.name,
            role: req.user.role,
            notes: 'Leave request submitted by applicant.',
            timestamp: new Date(),
          },
        ],
      });
    } catch {
      const leaveId = `leave_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
      leaveRecord = {
        _id: leaveId,
        id: leaveId,
        memberId: req.user.id || req.user._id,
        memberName: req.user.name,
        memberEmail: req.user.email,
        department: userDept,
        leaveType: chosenType,
        startDate: start,
        endDate: end,
        reason: reason.trim(),
        supportingDoc: supportingDoc || '',
        status: 'pending',
        history: [
          {
            status: 'pending',
            changedBy: req.user.name,
            role: req.user.role,
            notes: 'Leave request submitted by applicant.',
            timestamp: new Date(),
          },
        ],
        createdAt: new Date(),
      };
      setMemoryLeave(leaveRecord);
    }

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'LEAVE_REQUEST_SUBMITTED',
      module: 'LEAVE_MANAGEMENT',
      targetId: leaveRecord._id?.toString() || leaveRecord.id,
      targetModel: 'LeaveRequest',
      description: `${req.user.name} submitted a ${chosenType} leave request (${start.toLocaleDateString()} to ${end.toLocaleDateString()}).`,
    }).catch(() => null);

    const hrReviewers = getMemoryUsersList().filter((u) => ['hr', 'super_admin'].includes(u.role));
    for (const reviewer of hrReviewers) {
      await sendNotification({
        userId: reviewer.id || reviewer._id,
        title: 'New Leave Request Submitted',
        message: `${req.user.name} submitted a ${chosenType} leave request for ${userDept || 'General'}.`,
        type: 'info',
        category: 'leave',
        link: '/portal/hr?tab=leaves',
        dedupKey: `leave:submit:${leaveRecord._id?.toString() || leaveRecord.id}:${reviewer.id || reviewer._id}`,
      }).catch(() => null);
    }

    return res.status(201).json({
      success: true,
      message: 'Leave request submitted successfully.',
      leave: leaveRecord,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to submit leave request.' });
  }
});

/**
 * @route   GET /api/hr/leaves/my
 * @desc    Get authenticated user's own leave requests
 * @access  Protected (All authenticated staff & members)
 */
router.get('/leaves/my', protect, async (req, res) => {
  try {
    const userId = (req.user.id || req.user._id)?.toString();
    let leaves = [];
    try {
      leaves = await LeaveRequest.find({ memberId: userId }).sort({ createdAt: -1 });
    } catch {}

    if (!leaves || leaves.length === 0) {
      leaves = getMemoryLeavesList().filter((l) => l.memberId?.toString() === userId);
    }

    return res.json({ success: true, count: leaves.length, leaves });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to fetch personal leave requests.' });
  }
});

/**
 * @route   GET /api/hr/leaves/department
 * @desc    Get leave requests for the Department Head's department
 * @access  Protected (Department Heads of respective department & Super Admin)
 */
router.get('/leaves/department', protect, async (req, res) => {
  try {
    const isDeptHead = req.user.role.startsWith('dept_');
    const isSuperAdmin = req.user.role === 'super_admin';

    if (!isDeptHead && !isSuperAdmin) {
      return res.status(403).json({
        success: false,
        error: 'Forbidden: Only Department Heads or Super Admin can view department leave requests.',
      });
    }

    const deptName = isDeptHead ? DEPT_ROLE_MAP[req.user.role]?.name : req.query.department;
    if (!deptName && !isSuperAdmin) {
      return res.status(400).json({ success: false, error: 'Department could not be identified.' });
    }

    let leaves = [];
    try {
      const filter = deptName ? { department: deptName } : {};
      leaves = await LeaveRequest.find(filter).sort({ createdAt: -1 });
    } catch {}

    if (!leaves || leaves.length === 0) {
      leaves = getMemoryLeavesList();
      if (deptName) leaves = leaves.filter((l) => l.department === deptName);
    }

    return res.json({ success: true, count: leaves.length, department: deptName, leaves });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to fetch department leaves.' });
  }
});

/**
 * @route   GET /api/hr/leaves
 * @desc    List all organization leave requests with filters
 * @access  Protected (Super Admin & HR Only)
 */
router.get('/leaves', protect, authorize('super_admin', 'hr'), async (req, res) => {
  try {
    const { department, status, leaveType } = req.query;
    let leaves = [];
    try {
      const filter = {};
      if (department && department !== 'all') filter.department = department;
      if (status && status !== 'all') filter.status = status;
      if (leaveType && leaveType !== 'all') filter.leaveType = leaveType;
      leaves = await LeaveRequest.find(filter).sort({ createdAt: -1 });
    } catch {}

    if (!leaves || leaves.length === 0) {
      leaves = getMemoryLeavesList();
      if (department && department !== 'all') leaves = leaves.filter((l) => l.department === department);
      if (status && status !== 'all') leaves = leaves.filter((l) => l.status === status);
      if (leaveType && leaveType !== 'all') leaves = leaves.filter((l) => l.leaveType === leaveType);
    }

    return res.json({ success: true, count: leaves.length, leaves });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to fetch leave requests.' });
  }
});

/**
 * @route   GET /api/hr/leaves/:id
 * @desc    Get single leave request details
 * @access  Protected (Super Admin, HR, Department Head of same department, or Applicant)
 */
router.get('/leaves/:id', protect, async (req, res) => {
  try {
    const { id } = req.params;
    let leave = null;
    try {
      leave = await LeaveRequest.findById(id);
    } catch {}
    if (!leave) leave = memoryLeaves.get(id);

    if (!leave) {
      return res.status(404).json({ success: false, error: 'Leave request not found.' });
    }

    const currentUserId = (req.user.id || req.user._id)?.toString();
    const isOwner = leave.memberId?.toString() === currentUserId;
    const isSuperAdmin = req.user.role === 'super_admin';
    const isHR = req.user.role === 'hr';
    const isSameDeptHead =
      req.user.role.startsWith('dept_') && DEPT_ROLE_MAP[req.user.role]?.name === leave.department;

    if (!isOwner && !isSuperAdmin && !isHR && !isSameDeptHead) {
      return res.status(403).json({
        success: false,
        error: 'Forbidden: You do not have permission to view this leave request.',
      });
    }

    return res.json({ success: true, leave });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to fetch leave request.' });
  }
});

/**
 * @route   PATCH /api/hr/leaves/:id/review
 * @desc    Approve or reject a leave request
 * @access  Protected (Super Admin, or Department Head / Director of that department; HR Head/Director for HR)
 */
router.patch('/leaves/:id/review', protect, async (req, res) => {
  try {
    const { id } = req.params;
    const { action, notes } = req.body;

    if (!action || !['approve', 'reject'].includes(action)) {
      return res.status(400).json({
        success: false,
        error: "Action must be either 'approve' or 'reject'.",
      });
    }

    let leave = null;
    try {
      leave = await LeaveRequest.findById(id);
    } catch {}
    if (!leave) leave = memoryLeaves.get(id);

    if (!leave) {
      return res.status(404).json({ success: false, error: 'Leave request not found.' });
    }

    const currentUserId = (req.user.id || req.user._id)?.toString();
    const isOwner = leave.memberId?.toString() === currentUserId;

    // Anti-self-approval rule: Members/leads cannot approve their own leave request!
    if (isOwner) {
      return res.status(403).json({
        success: false,
        error: 'Forbidden: Anti-self-approval rule prevents approving or rejecting your own leave request.',
      });
    }

    const isSuperAdmin = req.user.role === 'super_admin';
    const isHR = req.user.role === 'hr';
    const hrDesig = isHR ? normalizeDesignation(req.user.designation) : null;

    // 1. HR Member view-only check
    if (isHR && ['hr_member', 'hr_assistant'].includes(hrDesig)) {
      return res.status(403).json({
        success: false,
        error: 'Forbidden: HR Team Members hold view-only access and cannot review leave requests.',
      });
    }

    // 2. Departmental boundary check
    const isOperationalDept = VALID_DEPARTMENTS.includes(leave.department) && leave.department !== 'HR';
    const isSameDeptHeadOrDirector =
      req.user.role.startsWith('dept_') &&
      DEPT_ROLE_MAP[req.user.role]?.name === leave.department &&
      ['head', 'director'].includes(normalizeDesignation(req.user.designation));

    if (isOperationalDept) {
      // For operational departments, HR (even HR Head/Director) CANNOT approve! Only Dept Head/Director or Super Admin
      if (isHR && !isSuperAdmin) {
        return res.status(403).json({
          success: false,
          error: `Forbidden: Operational department leave requests must be approved by the respective Department Head or Director. HR leadership cannot approve operational leaves.`,
        });
      }
      if (!isSuperAdmin && !isSameDeptHeadOrDirector) {
        return res.status(403).json({
          success: false,
          error: `Forbidden: Only Super Admin or the ${leave.department} Department Head / Director can review this leave request.`,
        });
      }
    } else if (leave.department === 'HR') {
      // HR department leaves can be approved by Super Admin or HR Head / HR Director
      const canApproveHR = isSuperAdmin || (isHR && ['hr_head', 'hr_director'].includes(hrDesig));
      if (!canApproveHR) {
        return res.status(403).json({
          success: false,
          error: 'Forbidden: Only Super Admin or HR Head / Director can review HR leave requests.',
        });
      }
    } else {
      if (!isSuperAdmin && !isSameDeptHeadOrDirector) {
        return res.status(403).json({
          success: false,
          error: 'Forbidden: Insufficient authorization to review this leave request.',
        });
      }
    }

    const newStatus = action === 'approve' ? 'approved' : 'rejected';
    leave.status = newStatus;
    leave.reviewedBy = req.user.id || req.user._id;
    leave.reviewedByName = req.user.name;
    leave.reviewedAt = new Date();
    leave.reviewNotes = notes || (action === 'approve' ? 'Leave approved.' : 'Leave rejected.');

    if (!leave.history) leave.history = [];
    leave.history.push({
      status: newStatus,
      changedBy: req.user.name,
      role: req.user.role,
      notes: notes || `Leave request ${newStatus}.`,
      timestamp: new Date(),
    });

    try {
      if (leave.save) await leave.save();
      else setMemoryLeave(leave);
    } catch {
      setMemoryLeave(leave);
    }

    // Create Notification for the member with deduplication
    await sendNotification({
      userId: leave.memberId,
      title: `Leave Request ${newStatus.toUpperCase()}`,
      message: `Your leave request from ${new Date(leave.startDate).toLocaleDateString()} to ${new Date(leave.endDate).toLocaleDateString()} has been ${newStatus} by ${req.user.name}.`,
      type: action === 'approve' ? 'success' : 'warning',
      category: 'leave',
      link: '/portal/member?tab=leaves',
      dedupKey: `leave:review:${id}:${newStatus}`,
    }).catch(() => null);

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: action === 'approve' ? 'LEAVE_REQUEST_APPROVED' : 'LEAVE_REQUEST_REJECTED',
      module: 'LEAVE_MANAGEMENT',
      targetId: id,
      targetModel: 'LeaveRequest',
      description: `${req.user.name} (${req.user.role}) ${action}d leave request for ${leave.memberName}.`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: `Leave request has been ${newStatus}.`,
      leave,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to process leave review.' });
  }
});

// ---------------------------------------------------------------------------
// 5. HR DATA EXPORT (Excel .xlsx and CSV with UTF-8 BOM)
// ---------------------------------------------------------------------------

/**
 * @route   GET /api/hr/export/applications
 * @desc    Export candidate applications in .xlsx or .csv format
 * @access  Protected (Super Admin, HR Head, HR Director, HR In-charge)
 */
router.get('/export/applications', protect, requireHRExport, async (req, res) => {
  try {
    const { format = 'csv', status, department, source, startDate, endDate, assignedInterviewer } = req.query;

    let apps = [];
    try {
      const filter = {};
      if (status && status !== 'all') filter.status = status;
      if (department && department !== 'all') {
        filter.$or = [{ department }, { areaOfInterest: { $regex: department, $options: 'i' } }];
      }
      if (source && source !== 'all') filter.source = source;
      if (assignedInterviewer) filter.assignedInterviewer = assignedInterviewer;
      if (startDate || endDate) {
        filter.createdAt = {};
        if (startDate) filter.createdAt.$gte = new Date(startDate);
        if (endDate) filter.createdAt.$lte = new Date(endDate);
      }
      apps = await Application.find(filter).sort({ createdAt: -1 });
    } catch {}

    if (!apps || apps.length === 0) {
      apps = getMemoryApplicationsList();
      if (status && status !== 'all') apps = apps.filter((a) => a.status === status);
      if (department && department !== 'all') {
        const d = department.toLowerCase();
        apps = apps.filter((a) => a.department?.toLowerCase() === d || a.areaOfInterest?.toLowerCase().includes(d));
      }
      if (source && source !== 'all') apps = apps.filter((a) => a.source === source);
      if (assignedInterviewer) {
        apps = apps.filter(
          (a) =>
            a.assignedInterviewer?.toString() === assignedInterviewer.toString() ||
            a.interviewDetails?.interviewerId?.toString() === assignedInterviewer.toString()
        );
      }
      if (startDate) apps = apps.filter((a) => new Date(a.createdAt) >= new Date(startDate));
      if (endDate) apps = apps.filter((a) => new Date(a.createdAt) <= new Date(endDate));
    }

    const rows = apps.map((a) => ({
      'Application ID': a._id?.toString() || a.id || a.submissionId || '',
      'Submission ID': a.submissionId || '',
      'Full Name': a.fullName || '',
      'Email': a.email || '',
      'Phone': a.phoneNumber || '',
      'City': a.city || '',
      'Age': a.age || '',
      'Department / Area': a.department || a.areaOfInterest || '',
      'Source': a.source || '',
      'Status': a.status || '',
      'Assigned Interviewer':
        a.interviewDetails?.interviewerName ||
        (typeof a.assignedInterviewer === 'string' ? a.assignedInterviewer : '') ||
        '',
      'Interview Recommendation': a.interviewDetails?.recommendation || '',
      'Decision': a.decisionDetails?.decision || '',
      'Decision Notes': a.decisionDetails?.decisionNotes || '',
      'Decided By': a.decisionDetails?.decidedByName || '',
      'Submitted At': a.createdAt ? new Date(a.createdAt).toISOString() : '',
    }));

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'HR_DATA_EXPORTED',
      module: 'HR_MANAGEMENT',
      targetModel: 'Application',
      description: `${req.user.name} exported ${rows.length} applications in ${format.toUpperCase()} format.`,
    }).catch(() => null);

    if (format.toLowerCase() === 'xlsx') {
      const ws = XLSX.utils.json_to_sheet(rows.length > 0 ? rows : [{ 'No Data': 'No applications match filter criteria' }]);
      const wb = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(wb, ws, 'Applications');
      const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition', `attachment; filename="hr_applications_${Date.now()}.xlsx"`);
      return res.send(buf);
    }

    // Default CSV
    const headers = [
      'Application ID',
      'Submission ID',
      'Full Name',
      'Email',
      'Phone',
      'City',
      'Age',
      'Department / Area',
      'Source',
      'Status',
      'Assigned Interviewer',
      'Interview Recommendation',
      'Decision',
      'Decision Notes',
      'Decided By',
      'Submitted At',
    ];
    let csvStr = headers.map(escapeCsv).join(',') + '\r\n';
    rows.forEach((r) => {
      csvStr += headers.map((h) => escapeCsv(r[h])).join(',') + '\r\n';
    });
    const bom = Buffer.from([0xef, 0xbb, 0xbf]);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="hr_applications_${Date.now()}.csv"`);
    return res.send(Buffer.concat([bom, Buffer.from(csvStr, 'utf-8')]));
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to export applications.' });
  }
});

/**
 * @route   GET /api/hr/export/leaves
 * @desc    Export leave requests in .xlsx or .csv format
 * @access  Protected (Super Admin, HR Head, HR Director, HR In-charge)
 */
router.get('/export/leaves', protect, requireHRExport, async (req, res) => {
  try {
    const { format = 'csv', department, status, leaveType, startDate, endDate } = req.query;

    let leaves = [];
    try {
      const filter = {};
      if (department && department !== 'all') filter.department = department;
      if (status && status !== 'all') filter.status = status;
      if (leaveType && leaveType !== 'all') filter.leaveType = leaveType;
      if (startDate || endDate) {
        filter.startDate = {};
        if (startDate) filter.startDate.$gte = new Date(startDate);
        if (endDate) filter.startDate.$lte = new Date(endDate);
      }
      leaves = await LeaveRequest.find(filter).sort({ createdAt: -1 });
    } catch {}

    if (!leaves || leaves.length === 0) {
      leaves = getMemoryLeavesList();
      if (department && department !== 'all') leaves = leaves.filter((l) => l.department === department);
      if (status && status !== 'all') leaves = leaves.filter((l) => l.status === status);
      if (leaveType && leaveType !== 'all') leaves = leaves.filter((l) => l.leaveType === leaveType);
      if (startDate) leaves = leaves.filter((l) => new Date(l.startDate) >= new Date(startDate));
      if (endDate) leaves = leaves.filter((l) => new Date(l.startDate) <= new Date(endDate));
    }

    const rows = leaves.map((l) => ({
      'Leave ID': l._id?.toString() || l.id || '',
      'Member Name': l.memberName || '',
      'Member Email': l.memberEmail || '',
      'Department': l.department || '',
      'Leave Type': l.leaveType || '',
      'Start Date': l.startDate ? new Date(l.startDate).toISOString().split('T')[0] : '',
      'End Date': l.endDate ? new Date(l.endDate).toISOString().split('T')[0] : '',
      'Reason': l.reason || '',
      'Status': l.status || '',
      'Reviewed By': l.reviewedByName || '',
      'Reviewed At': l.reviewedAt ? new Date(l.reviewedAt).toISOString() : '',
      'Review Notes': l.reviewNotes || '',
      'Submitted At': l.createdAt ? new Date(l.createdAt).toISOString() : '',
    }));

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'HR_DATA_EXPORTED',
      module: 'HR_MANAGEMENT',
      targetModel: 'LeaveRequest',
      description: `${req.user.name} exported ${rows.length} leave records in ${format.toUpperCase()} format.`,
    }).catch(() => null);

    if (format.toLowerCase() === 'xlsx') {
      const ws = XLSX.utils.json_to_sheet(rows.length > 0 ? rows : [{ 'No Data': 'No leaves match filter criteria' }]);
      const wb = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(wb, ws, 'Leaves');
      const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition', `attachment; filename="hr_leaves_${Date.now()}.xlsx"`);
      return res.send(buf);
    }

    // Default CSV
    const headers = [
      'Leave ID',
      'Member Name',
      'Member Email',
      'Department',
      'Leave Type',
      'Start Date',
      'End Date',
      'Reason',
      'Status',
      'Reviewed By',
      'Reviewed At',
      'Review Notes',
      'Submitted At',
    ];
    let csvStr = headers.map(escapeCsv).join(',') + '\r\n';
    rows.forEach((r) => {
      csvStr += headers.map((h) => escapeCsv(r[h])).join(',') + '\r\n';
    });
    const bom = Buffer.from([0xef, 0xbb, 0xbf]);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="hr_leaves_${Date.now()}.csv"`);
    return res.send(Buffer.concat([bom, Buffer.from(csvStr, 'utf-8')]));
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to export leaves.' });
  }
});

// ---------------------------------------------------------------------------
// 6. DEPARTMENT-WISE OFFICIAL ANNOUNCEMENTS
// Exclusively authorized for HR Coordination In-charge (and Super Admin)
// ---------------------------------------------------------------------------

/**
 * @route   POST /api/hr/announcements
 * @desc    Dispatch official announcement to a department or all departments
 * @access  Protected (HR Coordination In-charge ONLY & Super Admin)
 */
router.post('/announcements', protect, requireHRCoordinationIncharge, async (req, res) => {
  try {
    const { title, message, targetDepartment, targetDepartmentCode } = req.body;

    if (!title || !message) {
      return res.status(400).json({ success: false, error: 'Title and message are required.' });
    }

    const targetDept = targetDepartment || 'All';
    if (targetDept !== 'All' && !VALID_DEPARTMENTS.includes(targetDept)) {
      return res.status(400).json({
        success: false,
        error: `Invalid department '${targetDept}'. Valid: All, ${VALID_DEPARTMENTS.join(', ')}.`,
      });
    }

    const announcementId = `ANN_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;

    // Find all users in target department to calculate recipient count and dispatch notifications
    let recipients = [];
    try {
      const userFilter = targetDept === 'All' ? { status: 'active' } : { department: targetDept, status: 'active' };
      recipients = await User.find(userFilter).select('_id id name email');
    } catch {}

    if (!recipients || recipients.length === 0) {
      recipients = getMemoryUsersList().filter((u) => {
        if (targetDept === 'All') return true;
        return u.department?.toLowerCase() === targetDept.toLowerCase();
      });
    }

    const resolvedCode =
      targetDepartmentCode ||
      (targetDept === 'All'
        ? 'ALL'
        : Object.values(DEPT_ROLE_MAP).find((d) => d.name === targetDept)?.code || 'GEN');

    let announcement = null;
    try {
      announcement = await Announcement.create({
        announcementId,
        title: title.trim(),
        message: message.trim(),
        targetDepartment: targetDept,
        targetDepartmentCode: resolvedCode,
        senderId: req.user.id || req.user._id,
        senderName: req.user.name,
        senderRole: req.user.role,
        senderDesignation: req.user.designation || 'hr_coordination_incharge',
        recipientCount: recipients.length,
        status: 'published',
      });
    } catch {
      announcement = {
        _id: announcementId,
        id: announcementId,
        announcementId,
        title: title.trim(),
        message: message.trim(),
        targetDepartment: targetDept,
        targetDepartmentCode: resolvedCode,
        senderId: req.user.id || req.user._id,
        senderName: req.user.name,
        senderRole: req.user.role,
        senderDesignation: req.user.designation || 'hr_coordination_incharge',
        recipientCount: recipients.length,
        status: 'published',
        readBy: [],
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      setMemoryAnnouncement(announcement);
    }

    // Dispatch notifications to all recipient members
    for (const member of recipients) {
      const memberId = member._id?.toString() || member.id?.toString();
      if (!memberId) continue;
      await sendNotification({
        userId: memberId,
        title: `Official Announcement: ${title}`,
        message: `${req.user.name} (HR Coordination): ${message.substring(0, 100)}${message.length > 100 ? '...' : ''}`,
        type: 'info',
        category: 'announcement',
        link: '/portal?tab=announcements',
        dedupKey: `announcement:${announcementId}:${memberId}`,
      }).catch(() => null);
    }

    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'DEPARTMENT_ANNOUNCEMENT_DISPATCHED',
      module: 'HR_MANAGEMENT',
      targetId: announcementId,
      targetModel: 'Announcement',
      description: `${req.user.name} dispatched announcement '${title}' to target department '${targetDept}' (${recipients.length} recipients).`,
    }).catch(() => null);

    return res.status(201).json({
      success: true,
      message: `Official department announcement dispatched to ${targetDept} (${recipients.length} recipients).`,
      announcement,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to dispatch announcement.' });
  }
});

/**
 * @route   GET /api/hr/announcements
 * @desc    List all announcements sent by HR
 * @access  Protected (Super Admin & HR)
 */
router.get('/announcements', protect, authorize('super_admin', 'hr'), async (req, res) => {
  try {
    let announcements = [];
    try {
      announcements = await Announcement.find().sort({ createdAt: -1 });
    } catch {}

    if (!announcements || announcements.length === 0) {
      announcements = getMemoryAnnouncementsList();
    }

    return res.json({ success: true, count: announcements.length, announcements });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to fetch announcements.' });
  }
});

/**
 * @route   GET /api/hr/announcements/department/:department
 * @desc    List announcements visible to a department (or All)
 * @access  Protected (Members of that department, HR, or Super Admin)
 */
router.get('/announcements/department/:department', protect, async (req, res) => {
  try {
    const { department } = req.params;
    const isSuperAdmin = req.user.role === 'super_admin';
    const isHR = req.user.role === 'hr';
    const userDept = req.user.department || (req.user.role.startsWith('dept_') ? DEPT_ROLE_MAP[req.user.role]?.name : null);

    if (!isSuperAdmin && !isHR && userDept?.toLowerCase() !== department.toLowerCase() && department !== 'All') {
      return res.status(403).json({
        success: false,
        error: `Forbidden: You can only view announcements for your assigned department '${userDept || 'unassigned'}'.`,
      });
    }

    let announcements = [];
    try {
      const filter = {
        $or: [{ targetDepartment: department }, { targetDepartment: 'All' }],
      };
      announcements = await Announcement.find(filter).sort({ createdAt: -1 });
    } catch {}

    if (!announcements || announcements.length === 0) {
      announcements = getMemoryAnnouncementsList().filter(
        (a) => a.targetDepartment === 'All' || a.targetDepartment?.toLowerCase() === department.toLowerCase()
      );
    }

    return res.json({ success: true, count: announcements.length, announcements });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to fetch department announcements.' });
  }
});

// ---------------------------------------------------------------------------
// 7. HR OVERVIEW & ANALYTICS
// ---------------------------------------------------------------------------

/**
 * @route   GET /api/hr/overview
 * @desc    Comprehensive HR dashboard metrics and recent activities
 * @access  Protected (Super Admin & HR Only)
 */
router.get('/overview', protect, authorize('super_admin', 'hr'), async (req, res) => {
  try {
    let users = [];
    try {
      users = await User.find().select('-password');
    } catch {}
    if (!users || users.length === 0) users = getMemoryUsersList();

    let applications = [];
    try {
      applications = await Application.find();
    } catch {}
    if (!applications || applications.length === 0) applications = getMemoryApplicationsList();

    let campaigns = [];
    try {
      campaigns = await Campaign.find();
    } catch {}
    if (!campaigns || campaigns.length === 0) campaigns = getMemoryCampaignsList();

    let leaves = [];
    try {
      leaves = await LeaveRequest.find();
    } catch {}
    if (!leaves || leaves.length === 0) leaves = getMemoryLeavesList();

    // Department employee breakdown (dynamically derived from genuine database departments)
    let activeDepts = [];
    try {
      activeDepts = await Department.find({ status: 'active' }).sort({ name: 1 });
    } catch {}

    const departmentDistribution = activeDepts.map((dept) => ({
      name: dept.name,
      code: dept.code,
      count: users.filter((u) => u.department === dept.name || u.departmentCode === dept.code).length,
    }));

    return res.json({
      success: true,
      metrics: {
        totalEmployees: users.length,
        activeEmployees: users.filter((u) => u.status === 'active').length,
        activeCampaigns: campaigns.filter((c) => c.status === 'active').length,
        totalApplications: applications.length,
        pendingApplications: applications.filter((a) => ['submitted', 'pending', 'under_review'].includes(a.status)).length,
        shortlistedApplications: applications.filter((a) => a.status === 'shortlisted').length,
        interviewingApplications: applications.filter((a) => a.status === 'interview_scheduled').length,
        selectedApplications: applications.filter((a) => a.status === 'selected').length,
        rejectedApplications: applications.filter((a) => a.status === 'rejected').length,
        pendingLeaves: leaves.filter((l) => l.status === 'pending').length,
        approvedLeaves: leaves.filter((l) => l.status === 'approved').length,
      },
      departmentDistribution,
      recentApplications: applications.slice(-6).reverse(),
      recentLeaves: leaves.slice(-6).reverse(),
      campaigns,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to retrieve HR overview.' });
  }
});

// ===========================================================================
// ACCOUNT CREATION & ACTIVATION LINK MANAGEMENT (Phase D.2.2.6)
// ===========================================================================

/**
 * @route   POST /api/hr/accounts
 * @desc    Create a new portal user account and generate single-use 7-day activation link
 * @access  Protected (Super Admin, HR Head, HR Director, HR Coordination In-charge)
 */
router.post('/accounts', protect, requireAccountCreateAuthority, async (req, res) => {
  try {
    const { name, email, role, department, designation, phoneNumber } = req.body;

    if (!name || !email || !role) {
      return res.status(400).json({ success: false, error: 'Name, email, and role are required.' });
    }

    const normalizedEmail = email.toLowerCase().trim();

    if (!ALLOWED_ROLES.includes(role)) {
      return res.status(400).json({ success: false, error: `Invalid role '${role}'.` });
    }

    // Privilege Escalation Protection: HR cannot create Super Admin accounts
    if (role === 'super_admin' && req.user.role !== 'super_admin') {
      return res.status(403).json({
        success: false,
        error: 'Privilege escalation rejected: HR personnel cannot create Super Admin accounts.',
      });
    }

    // Check duplicate account
    let existingUser = null;
    try {
      existingUser = await User.findOne({ email: normalizedEmail });
    } catch {}
    if (!existingUser) {
      existingUser = getMemoryUsersList().find((u) => u.email === normalizedEmail);
    }
    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: `User account with email '${normalizedEmail}' already exists.`,
      });
    }

    // Role-designation validation
    let resolvedDesignation = null;
    if (designation) {
      const validation = validateRoleDesignation(role, designation);
      if (!validation.valid) {
        return res.status(400).json({ success: false, error: validation.error });
      }
      // If caller is HR (not Super Admin), HR cannot appoint operational Department Heads or Directors, or HR Head
      if (req.user.role !== 'super_admin') {
        const normalized = validation.designation;
        if (['head', 'director'].includes(normalized) && role !== 'hr') {
          return res.status(403).json({
            success: false,
            error: 'Forbidden: Appointing operational Department Heads and Directors requires Super Admin authorization.',
          });
        }
        if (normalized === 'hr_head') {
          return res.status(403).json({
            success: false,
            error: 'Forbidden: Appointing an HR Head requires Super Admin authorization.',
          });
        }
      }
      resolvedDesignation = validation.designation;
    }

    // Resolve department
    let resolvedDept = department || null;
    let resolvedDeptCode = null;
    if (role.startsWith('dept_')) {
      const mapped = DEPT_ROLE_MAP[role];
      resolvedDept = mapped?.name || department || 'Literature';
      resolvedDeptCode = mapped?.code || 'LIT';
    } else if (role === 'hr') {
      resolvedDept = 'HR';
      resolvedDeptCode = 'HR';
    } else if (role === 'finance') {
      resolvedDept = 'Finance';
      resolvedDeptCode = 'FIN';
    } else if (role === 'super_admin') {
      resolvedDept = department || 'Administration';
      resolvedDeptCode = 'ADM';
    } else {
      resolvedDept = department || 'Literature';
      const deptEntry = Object.values(DEPT_ROLE_MAP).find(
        (d) => d.name.toLowerCase() === (resolvedDept || '').toLowerCase()
      );
      resolvedDeptCode = deptEntry ? deptEntry.code : 'LIT';
    }

    // Cryptographic activation token: 32 bytes (stored as sha256 hash, raw in returned URL)
    const rawActivationToken = crypto.randomBytes(32).toString('hex');
    const hashedActivationToken = crypto.createHash('sha256').update(rawActivationToken).digest('hex');
    const activationExpires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

    // Temporary placeholder password
    const tempPassword = crypto.randomBytes(16).toString('hex');
    const hashedPassword = await bcrypt.hash(tempPassword, 10);

    const userId = `usr_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    const newUser = {
      _id: userId,
      id: userId,
      name: name.trim(),
      email: normalizedEmail,
      password: hashedPassword,
      role,
      department: resolvedDept,
      departmentCode: resolvedDeptCode,
      designation: resolvedDesignation,
      phoneNumber: phoneNumber?.trim() || '',
      status: 'inactive',
      activationToken: hashedActivationToken,
      activationExpires,
      isPrivilegedHR: role === 'super_admin' ? true : false,
      tokenVersion: 0,
      createdAt: new Date(),
    };

    try {
      await User.create(newUser);
    } catch {
      setMemoryUser(newUser);
    }

    const baseUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    const activationUrl = `${baseUrl}/portal/activate?token=${rawActivationToken}`;

    // Audit log (MUST NOT expose raw activation token)
    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'ACCOUNT_CREATED',
      module: 'HR',
      targetId: newUser.id,
      targetModel: 'User',
      description: `Account created for ${newUser.name} (${newUser.email}) with role '${newUser.role}' and designation '${newUser.designation || 'None'}'. Activation link generated (expires in 7 days).`,
    }).catch(() => null);

    const { password: _, activationToken: __, ...safeUser } = newUser;

    return res.status(201).json({
      success: true,
      message: 'Account created successfully. Provide the activation link to the user.',
      account: safeUser,
      user: safeUser,
      activation: {
        token: rawActivationToken,
        url: activationUrl,
        expiresAt: activationExpires,
      },
      activationUrl,
      activationToken: rawActivationToken,
      expiresAt: activationExpires,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to create user account.' });
  }
});

/**
 * @route   GET /api/hr/accounts
 * @desc    List all accounts with calculated activation status (Active, Pending Activation, Expired, Disabled)
 * @access  Protected (Super Admin, HR Head, HR Director, HR Coordination In-charge)
 */
router.get('/accounts', protect, requireAccountCreateAuthority, async (req, res) => {
  try {
    let users = [];
    try {
      users = await User.find().select('-password -activationToken -resetPasswordToken -refreshToken').lean();
    } catch {}

    if (!users || users.length === 0) {
      users = getMemoryUsersList();
    }

    const now = new Date();
    const sanitizedAccounts = users.map((u) => {
      const { password, activationToken, resetPasswordToken, refreshToken, ...safe } = u.toObject ? u.toObject() : { ...u };
      const safeId = safe._id ? safe._id.toString() : safe.id;

      let activationStatus = 'Active';
      if (safe.status === 'suspended') {
        activationStatus = 'Disabled';
      } else if (safe.status === 'inactive' || safe.activationExpires) {
        if (safe.activationExpires && new Date(safe.activationExpires) < now) {
          activationStatus = 'Expired';
        } else {
          activationStatus = 'Pending Activation';
        }
      } else if (safe.status === 'active') {
        activationStatus = 'Active';
      }

      return {
        ...safe,
        _id: safeId,
        id: safeId,
        activationStatus,
      };
    });

    return res.json({
      success: true,
      accounts: sanitizedAccounts,
      total: sanitizedAccounts.length,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to retrieve accounts list.' });
  }
});

/**
 * @route   POST /api/hr/accounts/:id/regenerate-activation
 * @desc    Regenerate single-use activation link (7 days) for pending or expired accounts
 * @access  Protected (Super Admin, HR Head, HR Director, HR Coordination In-charge)
 */
router.post('/accounts/:id/regenerate-activation', protect, requireAccountCreateAuthority, async (req, res) => {
  try {
    const { id } = req.params;

    let user = null;
    try {
      user = await User.findById(id);
    } catch {}
    if (!user) {
      user = getMemoryUsersList().find((u) => (u._id || u.id)?.toString() === id.toString());
    }

    if (!user) {
      return res.status(404).json({ success: false, error: 'Account not found.' });
    }

    // HR cannot regenerate activation for Super Admin accounts
    if (user.role === 'super_admin' && req.user.role !== 'super_admin') {
      return res.status(403).json({
        success: false,
        error: 'Forbidden: HR cannot regenerate activation for Super Admin accounts.',
      });
    }

    // If account is already active and not pending activation
    if (user.status === 'active' && !user.activationToken) {
      return res.status(400).json({
        success: false,
        error: 'Account is already activated. Use password reset for active accounts.',
      });
    }

    // Generate new raw cryptographic token & hash
    const rawActivationToken = crypto.randomBytes(32).toString('hex');
    const hashedActivationToken = crypto.createHash('sha256').update(rawActivationToken).digest('hex');
    const activationExpires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

    user.activationToken = hashedActivationToken;
    user.activationExpires = activationExpires;
    user.status = 'inactive';

    try {
      if (user.save) await user.save();
      else setMemoryUser(user);
    } catch {
      setMemoryUser(user);
    }

    const baseUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    const activationUrl = `${baseUrl}/portal/activate?token=${rawActivationToken}`;

    // Audit log (never log raw token)
    await AuditLog.create({
      actorId: req.user.id || req.user._id,
      actorName: req.user.name,
      actorRole: req.user.role,
      action: 'ACTIVATION_LINK_REGENERATED',
      module: 'HR',
      targetId: (user._id || user.id)?.toString(),
      targetModel: 'User',
      description: `Activation link regenerated for ${user.name} (${user.email}). New 7-day link issued.`,
    }).catch(() => null);

    return res.json({
      success: true,
      message: 'Activation link regenerated successfully.',
      activation: {
        token: rawActivationToken,
        url: activationUrl,
        expiresAt: activationExpires,
      },
      activationUrl,
      activationToken: rawActivationToken,
      expiresAt: activationExpires,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to regenerate activation link.' });
  }
});

module.exports = {
  router,
  setMemoryCampaign,
  getMemoryCampaignsList,
  setMemoryApplication,
  getMemoryApplicationsList,
  setMemoryLeave,
  getMemoryLeavesList,
  setMemoryAnnouncement,
  getMemoryAnnouncementsList,
};
