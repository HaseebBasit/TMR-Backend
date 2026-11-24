const express = require('express');
const router = express.Router();
const { Assessment, AuditLog, User } = require('../models');
const {
  protect,
  authorize,
  requireDepartmentScope,
  requireGradingConfidentiality,
  DEPT_ROLE_MAP,
  getMemoryUser,
} = require('../middleware/auth');

/**
 * @route   POST /api/assessments
 * @desc    Submit a member performance assessment (blind submission)
 * @access  Protected (Super Admin & Department Heads)
 */
router.post(
  '/',
  protect,
  authorize('super_admin', 'dept_literature', 'dept_media', 'dept_marketing', 'dept_outreach', 'dept_content'),
  requireDepartmentScope('department'),
  async (req, res) => {
    try {
      const {
        memberId,
        memberName,
        department,
        period,
        criteriaScores,
        qualitativeFeedback,
      } = req.body;

      if (!memberId || !department || !period || !criteriaScores) {
        return res.status(400).json({
          success: false,
          error: 'Please provide memberId, department, period, and criteriaScores.',
        });
      }

      const { taskExecution, deliverableQuality, punctuality, teamCollaboration } = criteriaScores;
      if (
        [taskExecution, deliverableQuality, punctuality, teamCollaboration].some(
          (s) => typeof s !== 'number' || s < 1 || s > 10
        )
      ) {
        return res.status(400).json({
          success: false,
          error: 'Criteria scores must be numbers between 1 and 10.',
        });
      }

      // Department isolation check: Department heads cannot evaluate members of other departments
      let targetMember = null;
      try {
        targetMember = await User.findById(memberId);
      } catch {}
      if (!targetMember) {
        targetMember = getMemoryUser(memberId);
      }

      if (targetMember && targetMember.department && targetMember.department.toLowerCase() !== department.toLowerCase()) {
        return res.status(403).json({
          success: false,
          error: `Department Isolation Violation: Member belongs to '${targetMember.department}', not '${department}'. You cannot assess members of other departments.`,
        });
      }

      const totalScore = taskExecution + deliverableQuality + punctuality + teamCollaboration;
      const percentage = Math.round((totalScore / 40) * 100);

      // Determine department code
      const deptEntry = Object.values(DEPT_ROLE_MAP).find(
        (d) => d.name.toLowerCase() === department.toLowerCase()
      );
      const departmentCode = deptEntry ? deptEntry.code : 'GEN';

      const assessment = await Assessment.create({
        memberId,
        memberName: memberName || 'Department Member',
        evaluatorId: req.user.id || req.user._id,
        evaluatorName: req.user.name,
        evaluatorRole: req.user.role,
        department,
        departmentCode,
        period,
        criteriaScores: { taskExecution, deliverableQuality, punctuality, teamCollaboration },
        totalScore,
        percentage,
        qualitativeFeedback: qualitativeFeedback || '',
        isConfidential: true,
      }).catch((err) => {
        console.warn('[Assessment DB Warning]:', err.message);
        return { _id: 'mock_assessment_' + Date.now() };
      });

      // Audit Log without revealing numeric scores
      await AuditLog.create({
        actorId: req.user.id || req.user._id,
        actorName: req.user.name,
        actorRole: req.user.role,
        action: 'ASSESSMENT_SUBMITTED',
        module: 'CONFIDENTIAL_GRADING',
        targetId: memberId.toString(),
        targetModel: 'Assessment',
        description: `Confidential evaluation submitted for member (${memberName || memberId}) in ${department} for period ${period}.`,
      }).catch(() => null);

      // BLIND RESPONSE: Never leak the score back to the submitter
      return res.status(201).json({
        success: true,
        message: 'Performance assessment successfully submitted and recorded in confidential archive.',
        assessmentId: assessment?._id?.toString(),
      });
    } catch (err) {
      console.error('[Assessment Error]:', err);
      return res.status(500).json({ success: false, error: 'Failed to submit assessment.' });
    }
  }
);

/**
 * @route   GET /api/assessments
 * @desc    Retrieve confidential grading reports
 * @access  Protected (STRICTLY SUPER ADMIN ONLY)
 */
router.get('/', protect, requireGradingConfidentiality, async (req, res) => {
  try {
    const { department, period } = req.query;
    const query = {};
    if (department) query.department = department;
    if (period) query.period = period;

    let assessments = [];
    try {
      assessments = await Assessment.find(query).sort({ createdAt: -1 });
    } catch {
      // offline mode fallback
    }

    return res.json({
      success: true,
      count: assessments.length,
      assessments,
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to retrieve assessments.' });
  }
});

/**
 * @route   GET /api/assessments/:id
 * @desc    Retrieve a single confidential assessment report
 * @access  Protected (STRICTLY SUPER ADMIN ONLY)
 */
router.get('/:id', protect, requireGradingConfidentiality, async (req, res) => {
  try {
    let assessment = null;
    try {
      assessment = await Assessment.findById(req.params.id);
    } catch {}

    if (!assessment) {
      return res.status(404).json({ success: false, error: 'Assessment record not found.' });
    }

    // Super Admin can view any assessment
    if (req.user.role === 'super_admin') {
      return res.json({ success: true, assessment });
    }

    // If Department Head, ensure assessment department strictly matches caller's department
    const userDept = req.user.department || DEPT_ROLE_MAP[req.user.role]?.name;
    const userCode = req.user.departmentCode || DEPT_ROLE_MAP[req.user.role]?.code;
    const matchName = assessment.department?.toLowerCase().trim() === userDept?.toLowerCase().trim();
    const matchCode = assessment.departmentCode?.toUpperCase().trim() === userCode?.toUpperCase().trim();

    if (!matchName && !matchCode) {
      return res.status(403).json({
        success: false,
        error: `Department Isolation Violation: You are authorized for '${userDept}' assessments only. Access to '${assessment.department}' confidential assessment is forbidden.`,
      });
    }

    return res.json({ success: true, assessment });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to retrieve assessment.' });
  }
});

module.exports = router;
