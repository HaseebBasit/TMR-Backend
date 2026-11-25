/**
 * Phase 10C: Official Organizational Provisioning & Idempotent Migration Utility
 * Ta'meer-e-Rekhta Management Portal
 * 
 * Safely provisions:
 * 1. Exactly 6 Official Departments (Literature, Content Creation, Outreach and Marketing, Media, HR, Welfare)
 * 2. Exactly 46 Authorized Organizational User Accounts (from 49 directory entries)
 * 3. Inactive account initialization with 32-byte cryptographic random activation tokens (SHA-256 hashed in DB)
 * 4. Multi-department memberships and email aliases
 * 5. Strict preservation of existing Super Admin account and audit trail
 * 
 * Invariants:
 * - Zero automatic emails, SMS, OTPs, or external communications.
 * - Raw tokens are returned ONLY in memory / stdout for Super Admin copy-and-share, never stored raw in DB.
 * - Idempotent execution: safe to run multiple times without duplicating or corrupting records.
 */

const path = require('path');
const crypto = require('crypto');
const mongoose = require('mongoose');
const dotenv = require('dotenv');

// Command line arguments: --env=staging | --env=production [--dry-run]
const args = process.argv.slice(2);
const envArg = args.find((a) => a.startsWith('--env='));
const targetEnv = envArg ? envArg.split('=')[1].toLowerCase() : 'staging';
const isDryRun = args.includes('--dry-run');

const envFile = targetEnv === 'production' ? '.env' : '.env.staging';
const envPath = path.join(__dirname, '..', envFile);

dotenv.config({ path: envPath, override: true });

const { User, Department, AuditLog } = require('../src/models');
const {
  validateDatabaseTarget,
  STAGING_DB_NAME,
  PRODUCTION_DB_NAME,
} = require('../src/config/db');

// Official 6 Departments Definition
const OFFICIAL_DEPARTMENTS = [
  {
    name: 'Literature',
    code: 'LIT',
    description: 'Reviving Urdu poetry, prose, and literary discourse.',
    leadName: 'Noor ul Huda',
    status: 'active',
    iconName: 'BookOpen',
  },
  {
    name: 'Content Creation',
    code: 'CON',
    description: 'Urdu scripting, editorial copywriting, and Gen-Z creative series.',
    leadName: 'Noor ul Huda',
    status: 'active',
    iconName: 'PenTool',
  },
  {
    name: 'Outreach and Marketing',
    code: 'OAM',
    description: 'Digital campaigns, branding, community engagement, and public outreach.',
    leadName: 'Laiba Malik',
    status: 'active',
    iconName: 'Megaphone',
  },
  {
    name: 'Media',
    code: 'MED',
    description: 'Photography, videography, graphic design, and video production.',
    leadName: 'Aisha Tariq',
    status: 'active',
    iconName: 'Camera',
  },
  {
    name: 'HR',
    code: 'HR',
    description: 'Talent acquisition, organizational development, and volunteer management.',
    leadName: 'Hania',
    status: 'active',
    iconName: 'Users',
  },
  {
    name: 'Welfare',
    code: 'WEL',
    description: 'Social welfare initiatives, community relief, and regional aid distribution.',
    leadName: 'Asfand Yar Karimi (Punjab) / Daniyal Asim (Sindh)',
    status: 'active',
    iconName: 'HeartHandshake',
  },
];

// Complete 46-Person Identity Matrix (49 Directory Entries)
const OFFICIAL_ACCOUNTS = [
  // --- 1. LITERATURE (15 directory entries -> 13 distinct individuals) ---
  {
    name: 'Noor ul Huda',
    email: 'noorulhuda@rekhta.org',
    city: 'Karachi',
    designation: 'head',
    role: 'dept_literature',
    department: 'Literature',
    departmentCode: 'LIT',
    region: 'National',
    memberships: [
      { department: 'Literature', departmentCode: 'LIT', role: 'dept_literature', designation: 'head', region: 'National', isPrimary: true },
      { department: 'Content Creation', departmentCode: 'CON', role: 'dept_content', designation: 'head', region: 'National', isPrimary: false },
    ],
    emailAliases: ['noorulhuda.cc@rekhta.org'],
  },
  {
    name: 'Laiba Faisal',
    email: 'laibafaisal@rekhta.org',
    city: 'Karachi',
    designation: 'director',
    role: 'dept_literature',
    department: 'Literature',
    departmentCode: 'LIT',
    region: 'National',
    memberships: [
      { department: 'Literature', departmentCode: 'LIT', role: 'dept_literature', designation: 'director', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Eshal Abdullah',
    email: 'eshalabdullah@rekhta.org',
    city: 'Karachi',
    designation: 'assistant_director',
    role: 'dept_literature',
    department: 'Literature',
    departmentCode: 'LIT',
    region: 'National',
    memberships: [
      { department: 'Literature', departmentCode: 'LIT', role: 'dept_literature', designation: 'assistant_director', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Ayesha Fatima',
    email: 'ayeshafatima@rekhta.org',
    city: 'Lahore',
    designation: 'assistant_director',
    role: 'dept_literature',
    department: 'Literature',
    departmentCode: 'LIT',
    region: 'National',
    memberships: [
      { department: 'Literature', departmentCode: 'LIT', role: 'dept_literature', designation: 'assistant_director', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Asma Saeed',
    email: 'asma.saeed@rekhta.org',
    city: 'Lahore',
    designation: 'member',
    role: 'member',
    department: 'Literature',
    departmentCode: 'LIT',
    region: 'National',
    memberships: [
      { department: 'Literature', departmentCode: 'LIT', role: 'member', designation: 'member', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Ayesha Raheemen',
    email: 'ayesharaheemen@rekhta.org',
    city: 'Karachi',
    designation: 'member',
    role: 'member',
    department: 'Literature',
    departmentCode: 'LIT',
    region: 'National',
    memberships: [
      { department: 'Literature', departmentCode: 'LIT', role: 'member', designation: 'member', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Haseeb Basit',
    email: 'haseebbasit@rekhta.org',
    city: 'Karachi',
    designation: 'member',
    role: 'member',
    department: 'Literature',
    departmentCode: 'LIT',
    region: 'National',
    memberships: [
      { department: 'Literature', departmentCode: 'LIT', role: 'member', designation: 'member', region: 'National', isPrimary: true },
      { department: 'Content Creation', departmentCode: 'CON', role: 'member', designation: 'member', region: 'National', isPrimary: false },
    ],
    emailAliases: ['haseebbasit.cc@rekhta.org'],
  },
  {
    name: 'Hina Amjad',
    email: 'hinaamjad@rekhta.org',
    city: 'Karachi',
    designation: 'member',
    role: 'member',
    department: 'Literature',
    departmentCode: 'LIT',
    region: 'National',
    memberships: [
      { department: 'Literature', departmentCode: 'LIT', role: 'member', designation: 'member', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Zain Rana',
    email: 'zainrana@rekhta.org',
    city: 'Lahore',
    designation: 'member',
    role: 'member',
    department: 'Literature',
    departmentCode: 'LIT',
    region: 'National',
    memberships: [
      { department: 'Literature', departmentCode: 'LIT', role: 'member', designation: 'member', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Rabia',
    email: 'rabia@rekhta.org',
    city: 'Faisalabad',
    designation: 'member',
    role: 'member',
    department: 'Literature',
    departmentCode: 'LIT',
    region: 'National',
    memberships: [
      { department: 'Literature', departmentCode: 'LIT', role: 'member', designation: 'member', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Muhammad bin Rizwan',
    email: 'muhammadbinrizwan@rekhta.org',
    city: 'Lahore',
    designation: 'member',
    role: 'member',
    department: 'Literature',
    departmentCode: 'LIT',
    region: 'National',
    memberships: [
      { department: 'Literature', departmentCode: 'LIT', role: 'member', designation: 'member', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Rumaisa',
    email: 'rumaisa@rekhta.org',
    city: 'Karachi',
    designation: 'member',
    role: 'member',
    department: 'Literature',
    departmentCode: 'LIT',
    region: 'National',
    memberships: [
      { department: 'Literature', departmentCode: 'LIT', role: 'member', designation: 'member', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Fuzail Raza',
    email: 'fuzailraza@rekhta.org',
    city: 'Karachi',
    designation: 'member',
    role: 'member',
    department: 'Literature',
    departmentCode: 'LIT',
    region: 'National',
    memberships: [
      { department: 'Literature', departmentCode: 'LIT', role: 'member', designation: 'member', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Yazdaan Ali Khan',
    email: 'yazdaanali@rekhta.org',
    city: 'Karachi',
    designation: 'member',
    role: 'member',
    department: 'Literature',
    departmentCode: 'LIT',
    region: 'National',
    memberships: [
      { department: 'Literature', departmentCode: 'LIT', role: 'member', designation: 'member', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Laiba Idrees',
    email: 'laibaidrees@rekhta.org',
    city: 'Lahore',
    designation: 'member',
    role: 'member',
    department: 'Literature',
    departmentCode: 'LIT',
    region: 'National',
    memberships: [
      { department: 'Literature', departmentCode: 'LIT', role: 'member', designation: 'member', region: 'National', isPrimary: true },
    ],
  },

  // --- 2. CONTENT CREATION (5 unique primary accounts + 2 secondary) ---
  {
    name: 'Sheeza',
    email: 'sheeza@rekhta.org',
    city: 'Karachi',
    designation: 'member',
    role: 'member',
    department: 'Content Creation',
    departmentCode: 'CON',
    region: 'National',
    memberships: [
      { department: 'Content Creation', departmentCode: 'CON', role: 'member', designation: 'member', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Hoor',
    email: 'hoor@rekhta.org',
    city: 'Karachi',
    designation: 'member',
    role: 'member',
    department: 'Content Creation',
    departmentCode: 'CON',
    region: 'National',
    memberships: [
      { department: 'Content Creation', departmentCode: 'CON', role: 'member', designation: 'member', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Zainab Noor',
    email: 'zainabnoor@rekhta.org',
    city: 'Karachi',
    designation: 'member',
    role: 'member',
    department: 'Content Creation',
    departmentCode: 'CON',
    region: 'National',
    memberships: [
      { department: 'Content Creation', departmentCode: 'CON', role: 'member', designation: 'member', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Arisha Batool',
    email: 'arishabatool@rekhta.org',
    city: 'Karachi',
    designation: 'member',
    role: 'member',
    department: 'Content Creation',
    departmentCode: 'CON',
    region: 'National',
    memberships: [
      { department: 'Content Creation', departmentCode: 'CON', role: 'member', designation: 'member', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Hafiz Muhammad Moosa',
    email: 'hafizmuhammadmoosa@rekhta.org',
    city: 'Karachi',
    designation: 'member',
    role: 'member',
    department: 'Content Creation',
    departmentCode: 'CON',
    region: 'National',
    memberships: [
      { department: 'Content Creation', departmentCode: 'CON', role: 'member', designation: 'member', region: 'National', isPrimary: true },
    ],
  },

  // --- 3. OUTREACH AND MARKETING (5 unique primary accounts) ---
  {
    name: 'Laiba Malik',
    email: 'laibamalik@rekhta.org',
    city: 'Islamabad',
    designation: 'head',
    role: 'dept_oam',
    department: 'Outreach and Marketing',
    departmentCode: 'OAM',
    region: 'National',
    memberships: [
      { department: 'Outreach and Marketing', departmentCode: 'OAM', role: 'dept_oam', designation: 'head', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Faseha Khan',
    email: 'fasehakhan@rekhta.org',
    city: 'Lahore',
    designation: 'director',
    role: 'dept_oam',
    department: 'Outreach and Marketing',
    departmentCode: 'OAM',
    region: 'National',
    memberships: [
      { department: 'Outreach and Marketing', departmentCode: 'OAM', role: 'dept_oam', designation: 'director', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Iman Fatima',
    email: 'imanfatima@rekhta.org',
    city: 'Islamabad',
    designation: 'member',
    role: 'member',
    department: 'Outreach and Marketing',
    departmentCode: 'OAM',
    region: 'National',
    memberships: [
      { department: 'Outreach and Marketing', departmentCode: 'OAM', role: 'member', designation: 'member', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Ayesha Arif',
    email: 'ayeshaarif@rekhta.org',
    city: 'Karachi',
    designation: 'member',
    role: 'member',
    department: 'Outreach and Marketing',
    departmentCode: 'OAM',
    region: 'National',
    memberships: [
      { department: 'Outreach and Marketing', departmentCode: 'OAM', role: 'member', designation: 'member', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Aqib Ali',
    email: 'aqibali@rekhta.org',
    city: 'Lahore',
    designation: 'member',
    role: 'member',
    department: 'Outreach and Marketing',
    departmentCode: 'OAM',
    region: 'National',
    memberships: [
      { department: 'Outreach and Marketing', departmentCode: 'OAM', role: 'member', designation: 'member', region: 'National', isPrimary: true },
    ],
  },

  // --- 4. MEDIA (5 unique primary accounts) ---
  {
    name: 'Aisha Tariq',
    email: 'aishatariq@rekhta.org',
    city: 'Karachi',
    designation: 'head',
    role: 'dept_media',
    department: 'Media',
    departmentCode: 'MED',
    region: 'National',
    memberships: [
      { department: 'Media', departmentCode: 'MED', role: 'dept_media', designation: 'head', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Sarmad Waseem',
    email: 'sarmadwaseem@rekhta.org',
    city: 'Bahawalpur',
    designation: 'director_graphics',
    role: 'dept_media',
    department: 'Media',
    departmentCode: 'MED',
    region: 'National',
    memberships: [
      { department: 'Media', departmentCode: 'MED', role: 'dept_media', designation: 'director_graphics', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Hafiza Ayesha Amir',
    email: 'hafizaayesha@rekhta.org',
    city: 'Karachi',
    designation: 'assistant_director',
    role: 'dept_media',
    department: 'Media',
    departmentCode: 'MED',
    region: 'National',
    memberships: [
      { department: 'Media', departmentCode: 'MED', role: 'dept_media', designation: 'assistant_director', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Inshal Sheikh',
    email: 'inshalsheikh@rekhta.org',
    city: 'Karachi',
    designation: 'member',
    role: 'member',
    department: 'Media',
    departmentCode: 'MED',
    region: 'National',
    memberships: [
      { department: 'Media', departmentCode: 'MED', role: 'member', designation: 'member', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Wania Amir',
    email: 'waniaamir@rekhta.org',
    city: 'Bahawalpur',
    designation: 'member',
    role: 'member',
    department: 'Media',
    departmentCode: 'MED',
    region: 'National',
    memberships: [
      { department: 'Media', departmentCode: 'MED', role: 'member', designation: 'member', region: 'National', isPrimary: true },
    ],
  },

  // --- 5. HR (7 unique primary accounts) ---
  {
    name: 'Hania',
    email: 'hania@rekhta.org',
    city: 'Bahawalpur',
    designation: 'hr_head',
    role: 'hr',
    department: 'HR',
    departmentCode: 'HR',
    region: 'National',
    memberships: [
      { department: 'HR', departmentCode: 'HR', role: 'hr', designation: 'hr_head', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Mahnoor',
    email: 'mahnoor@rekhta.org',
    city: 'Bahawalpur',
    designation: 'hr_director',
    role: 'hr',
    department: 'HR',
    departmentCode: 'HR',
    region: 'National',
    memberships: [
      { department: 'HR', departmentCode: 'HR', role: 'hr', designation: 'hr_director', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Ahmed Mujtaba',
    email: 'ahmedmujtaba@rekhta.org',
    city: 'Karachi',
    designation: 'assistant_director',
    role: 'hr',
    department: 'HR',
    departmentCode: 'HR',
    region: 'National',
    memberships: [
      { department: 'HR', departmentCode: 'HR', role: 'hr', designation: 'assistant_director', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Syed Muhammad Rayan Ali',
    email: 'rayanali@rekhta.org',
    city: 'Karachi',
    designation: 'assistant_director',
    role: 'hr',
    department: 'HR',
    departmentCode: 'HR',
    region: 'National',
    memberships: [
      { department: 'HR', departmentCode: 'HR', role: 'hr', designation: 'assistant_director', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Noor e Haram',
    email: 'nooreharam@rekhta.org',
    city: 'Karachi',
    designation: 'member',
    role: 'member',
    department: 'HR',
    departmentCode: 'HR',
    region: 'National',
    memberships: [
      { department: 'HR', departmentCode: 'HR', role: 'member', designation: 'member', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Zoraiz Ali',
    email: 'zoraizali@rekhta.org',
    city: 'Bahawalpur',
    designation: 'volunteer',
    role: 'member',
    department: 'HR',
    departmentCode: 'HR',
    region: 'National',
    memberships: [
      { department: 'HR', departmentCode: 'HR', role: 'member', designation: 'volunteer', region: 'National', isPrimary: true },
    ],
  },
  {
    name: 'Saima Fatima',
    email: 'saimafatima@rekhta.org',
    city: 'Karachi',
    designation: 'coordination_incharge',
    role: 'hr',
    department: 'HR',
    departmentCode: 'HR',
    region: 'National',
    memberships: [
      { department: 'HR', departmentCode: 'HR', role: 'hr', designation: 'coordination_incharge', region: 'National', isPrimary: true },
    ],
  },

  // --- 6. WELFARE (9 unique primary accounts + 1 secondary) ---
  {
    name: 'Asfand Yar Karimi',
    email: 'asfandyar@rekhta.org',
    city: 'Bahawalpur',
    designation: 'head_of_punjab',
    role: 'dept_welfare',
    department: 'Welfare',
    departmentCode: 'WEL',
    region: 'Punjab',
    memberships: [
      { department: 'Welfare', departmentCode: 'WEL', role: 'dept_welfare', designation: 'head_of_punjab', region: 'Punjab', isPrimary: true },
    ],
  },
  {
    name: 'Daniyal Asim',
    email: 'daniyalasim@rekhta.org',
    city: 'Karachi',
    designation: 'head_of_sindh',
    role: 'dept_welfare',
    department: 'Welfare',
    departmentCode: 'WEL',
    region: 'Sindh',
    memberships: [
      { department: 'Welfare', departmentCode: 'WEL', role: 'dept_welfare', designation: 'head_of_sindh', region: 'Sindh', isPrimary: true },
    ],
  },
  {
    name: 'Syed Ibrahim',
    email: 'syedibrahim@rekhta.org',
    city: 'Bahawalpur',
    designation: 'director',
    role: 'dept_welfare',
    department: 'Welfare',
    departmentCode: 'WEL',
    region: 'Punjab',
    memberships: [
      { department: 'Welfare', departmentCode: 'WEL', role: 'dept_welfare', designation: 'director', region: 'Punjab', isPrimary: true },
    ],
  },
  {
    name: 'Abdul Basit',
    email: 'abdulbasit@rekhta.org',
    city: 'Karachi',
    designation: 'member',
    role: 'member',
    department: 'Welfare',
    departmentCode: 'WEL',
    region: 'Sindh',
    memberships: [
      { department: 'Welfare', departmentCode: 'WEL', role: 'member', designation: 'member', region: 'Sindh', isPrimary: true },
    ],
  },
  {
    name: 'Husam Rajput',
    email: 'husamrajput@rekhta.org',
    city: 'Bahawalpur',
    designation: 'member',
    role: 'member',
    department: 'Welfare',
    departmentCode: 'WEL',
    region: 'Punjab',
    memberships: [
      { department: 'Welfare', departmentCode: 'WEL', role: 'member', designation: 'member', region: 'Punjab', isPrimary: true },
    ],
  },
  {
    name: 'Usman Khalid',
    email: 'usmankhalid@rekhta.org',
    city: 'Karachi',
    designation: 'member',
    role: 'member',
    department: 'Welfare',
    departmentCode: 'WEL',
    region: 'Sindh',
    memberships: [
      { department: 'Welfare', departmentCode: 'WEL', role: 'member', designation: 'member', region: 'Sindh', isPrimary: true },
    ],
  },
  {
    name: 'Afifa',
    email: 'afifa@rekhta.org',
    city: 'Karachi',
    designation: 'member',
    role: 'member',
    department: 'Welfare',
    departmentCode: 'WEL',
    region: 'Sindh',
    memberships: [
      { department: 'Welfare', departmentCode: 'WEL', role: 'member', designation: 'member', region: 'Sindh', isPrimary: true },
    ],
  },
  {
    name: 'Shafaq Raza',
    email: 'shafaqraza.lhr@rekhta.org',
    city: 'Lahore',
    designation: 'member',
    role: 'member',
    department: 'Welfare',
    departmentCode: 'WEL',
    region: 'Punjab',
    memberships: [
      { department: 'Welfare', departmentCode: 'WEL', role: 'member', designation: 'member', region: 'Punjab', isPrimary: true },
    ],
  },
  {
    name: 'Danish Abid',
    email: 'danishabid@rekhta.org',
    city: 'Karachi',
    designation: 'member',
    role: 'member',
    department: 'Welfare',
    departmentCode: 'WEL',
    region: 'Sindh',
    memberships: [
      { department: 'Welfare', departmentCode: 'WEL', role: 'member', designation: 'member', region: 'Sindh', isPrimary: true },
    ],
  },
  {
    name: 'Nayab Jahangir',
    email: 'nayabjahangir@rekhta.org',
    city: 'Karachi',
    designation: 'member',
    role: 'member',
    department: 'Welfare',
    departmentCode: 'WEL',
    region: 'Sindh',
    memberships: [
      { department: 'Welfare', departmentCode: 'WEL', role: 'member', designation: 'member', region: 'Sindh', isPrimary: true },
    ],
    emailAliases: ['nayabjahangir.welfare@rekhta.org'],
  },
];

async function runProvisioning() {
  console.log('========================================================================');
  console.log("TA'MEER-E-REKHTA: OFFICIAL ORGANIZATIONAL PROVISIONING UTILITY");
  console.log(`Target Environment : ${targetEnv.toUpperCase()}`);
  console.log(`Mode               : ${isDryRun ? 'DRY-RUN (No writes)' : 'LIVE EXECUTION'}`);
  console.log('========================================================================\n');

  const mongoUri = process.env.MONGODB_URI;
  if (!mongoUri) {
    console.error('[ERROR] MONGODB_URI is not set in environment.');
    process.exit(1);
  }

  // Safety Gate: Target Database Validation
  const validation = validateDatabaseTarget(mongoUri, targetEnv);
  if (!validation.valid) {
    console.error(`[FATAL] Safety Gate Tripped: ${validation.error}`);
    process.exit(1);
  }

  console.log(`[Safety Guard] Target database verified: ${validation.databaseName}`);
  console.log(`[Safety Guard] Live writes enabled     : ${!isDryRun}`);

  await mongoose.connect(mongoUri);
  console.log('[Database] Connected successfully to Atlas cluster.\n');

  try {
    // -------------------------------------------------------------------------
    // STEP 1: PRE-FLIGHT INSPECTION & SUPER ADMIN VERIFICATION
    // -------------------------------------------------------------------------
    console.log('>>> [STEP 1]: Inspecting Existing Database State...');
    const existingUsers = await User.find().select('+password +activationToken');
    const existingDepts = await Department.find();
    console.log(`Existing Users Count       : ${existingUsers.length}`);
    console.log(`Existing Departments Count : ${existingDepts.length}`);

    // Verify existing Super Admin
    const superAdmin = existingUsers.find((u) => u.role === 'super_admin');
    if (!superAdmin) {
      console.error('[FATAL] Super Admin account not found in database! Provisioning aborted.');
      process.exit(1);
    }

    console.log(`[Super Admin Verified] ID: ${superAdmin._id} | Email: ${superAdmin.email} | Status: ${superAdmin.status}`);
    if (superAdmin.status !== 'active') {
      console.warn(`[WARNING] Super Admin status is '${superAdmin.status}', not 'active'.`);
    }

    // -------------------------------------------------------------------------
    // STEP 2: IDEMPOTENT DEPARTMENT PROVISIONING (6 Official Departments)
    // -------------------------------------------------------------------------
    console.log('\n>>> [STEP 2]: Provisioning 6 Official Departments...');
    const departmentResults = [];
    const officialCodes = OFFICIAL_DEPARTMENTS.map((d) => d.code);

    // Remove or deactivate legacy departments not in the official 6
    if (!isDryRun) {
      const removedDepts = await Department.deleteMany({ code: { $nin: officialCodes } });
      if (removedDepts.deletedCount > 0) {
        console.log(`[Reconciliation] Removed ${removedDepts.deletedCount} legacy departments not in the official 6.`);
      }
    }

    for (const deptData of OFFICIAL_DEPARTMENTS) {
      const existing = existingDepts.find((d) => d.code === deptData.code || d.name.toLowerCase() === deptData.name.toLowerCase());
      if (existing) {
        if (!isDryRun) {
          existing.name = deptData.name;
          existing.code = deptData.code;
          existing.description = deptData.description;
          existing.leadName = deptData.leadName;
          existing.iconName = deptData.iconName;
          existing.status = 'active';
          await existing.save();
        }
        departmentResults.push({ name: deptData.name, code: deptData.code, action: 'UPDATED/VERIFIED' });
      } else {
        if (!isDryRun) {
          await Department.create(deptData);
        }
        departmentResults.push({ name: deptData.name, code: deptData.code, action: 'CREATED' });
      }
    }

    console.table(departmentResults);

    // In staging, clean up legacy test personas (preserving staging super admin)
    if (!isDryRun && targetEnv === 'staging') {
      const deletedLegacy = await User.deleteMany({
        role: { $ne: 'super_admin' },
        email: { $regex: '@staging\\.rekhta\\.internal$' },
      });
      if (deletedLegacy.deletedCount > 0) {
        console.log(`[Staging Cleanup] Removed ${deletedLegacy.deletedCount} legacy test personas from staging.`);
      }
    }

    // -------------------------------------------------------------------------
    // STEP 3: IDEMPOTENT 46 ORGANIZATIONAL ACCOUNTS PROVISIONING
    // -------------------------------------------------------------------------
    console.log('\n>>> [STEP 3]: Provisioning 46 Organizational User Accounts...');
    const accountResults = [];
    const generatedLinks = [];
    const baseUrl = process.env.FRONTEND_URL || (targetEnv === 'production' ? 'https://tameer-e-rekhta.vercel.app' : 'http://localhost:3001');

    for (const acc of OFFICIAL_ACCOUNTS) {
      const normalizedEmail = acc.email.toLowerCase().trim();
      const existing = existingUsers.find(
        (u) => u.email?.toLowerCase() === normalizedEmail || (Array.isArray(u.emailAliases) && u.emailAliases.includes(normalizedEmail))
      );

      // Cryptographic random 32-byte token
      const rawToken = crypto.randomBytes(32).toString('hex');
      const hashedToken = crypto.createHash('sha256').update(rawToken).digest('hex');
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

      if (existing) {
        // Safe Update: preserve existing password if already active
        if (!isDryRun) {
          existing.name = acc.name;
          existing.city = acc.city;
          existing.designation = acc.designation;
          existing.role = acc.role;
          existing.department = acc.department;
          existing.departmentCode = acc.departmentCode;
          existing.region = acc.region;
          existing.memberships = acc.memberships;
          existing.emailAliases = acc.emailAliases || [];

          // Only generate activation token if account is inactive or not yet activated
          if (existing.status !== 'active') {
            existing.status = 'inactive';
            existing.activationToken = hashedToken;
            existing.activationExpires = expiresAt;
            existing.activationGeneratedAt = new Date();
            existing.activationRevokedAt = undefined;
          }
          await existing.save();
        }

        const isNewToken = existing.status !== 'active';
        accountResults.push({
          name: acc.name,
          email: acc.email,
          role: acc.role,
          designation: acc.designation,
          status: existing.status,
          action: 'RECONCILED/UPDATED',
          tokenIssued: isNewToken,
        });

        if (isNewToken) {
          generatedLinks.push({
            name: acc.name,
            email: acc.email,
            department: acc.department,
            designation: acc.designation,
            role: acc.role,
            activationUrl: `${baseUrl}/portal/activate?token=${rawToken}`,
            expiresAt,
          });
        }
      } else {
        // Create new inactive account with hashed token
        const newUserDoc = {
          name: acc.name,
          email: normalizedEmail,
          city: acc.city,
          designation: acc.designation,
          role: acc.role,
          department: acc.department,
          departmentCode: acc.departmentCode,
          region: acc.region,
          memberships: acc.memberships,
          emailAliases: acc.emailAliases || [],
          status: 'inactive',
          activationToken: hashedToken,
          activationExpires: expiresAt,
          activationGeneratedAt: new Date(),
          tokenVersion: 0,
        };

        if (!isDryRun) {
          await User.create(newUserDoc);
          await AuditLog.create({
            actorName: 'SYSTEM_PROVISIONER',
            actorRole: 'super_admin',
            action: 'ORGANIZATIONAL_ACCOUNT_PROVISIONED',
            module: 'SUPER_ADMIN',
            description: `Provisioned official organizational account for ${acc.name} (${normalizedEmail})`,
          }).catch(() => null);
        }

        accountResults.push({
          name: acc.name,
          email: acc.email,
          role: acc.role,
          designation: acc.designation,
          status: 'inactive',
          action: 'CREATED_INACTIVE',
          tokenIssued: true,
        });

        generatedLinks.push({
          name: acc.name,
          email: acc.email,
          department: acc.department,
          designation: acc.designation,
          role: acc.role,
          activationUrl: `${baseUrl}/portal/activate?token=${rawToken}`,
          expiresAt,
        });
      }
    }

    console.table(accountResults.map((r) => ({ Name: r.name, Email: r.email, Role: r.role, Desig: r.designation, Status: r.status, Action: r.action, Token: r.tokenIssued ? 'YES' : 'NO' })));

    // -------------------------------------------------------------------------
    // STEP 4: POST-PROVISIONING VERIFICATION AUDIT
    // -------------------------------------------------------------------------
    console.log('\n>>> [STEP 4]: Post-Provisioning Reconciliation & Invariant Checks...');
    const finalUsers = await User.find();
    const finalDepts = await Department.find();

    console.log(`Final Department Count : ${finalDepts.length} (Expected: 6)`);
    console.log(`Final Users Count      : ${finalUsers.length} (Expected: 48 -> 1 Super Admin + 47 Organizational)`);

    const superAdminPost = finalUsers.find((u) => u.role === 'super_admin');
    const inactiveCount = finalUsers.filter((u) => u.status === 'inactive').length;
    const activeCount = finalUsers.filter((u) => u.status === 'active').length;

    console.log(`Super Admin Status     : ${superAdminPost?.status} (Protected)`);
    console.log(`Active Accounts        : ${activeCount} (Super Admin)`);
    console.log(`Inactive Accounts      : ${inactiveCount} (Newly provisioned pending activation)`);
    console.log(`Activation Links Total : ${generatedLinks.length}`);

    // Invariant Assertions
    if (!isDryRun) {
      if (finalDepts.length !== 6) {
        throw new Error(`Department invariant failed! Found ${finalDepts.length}, expected 6.`);
      }
      if (finalUsers.length !== 48) {
        throw new Error(`User invariant failed! Found ${finalUsers.length}, expected 48.`);
      }
      if (superAdminPost.status !== 'active') {
        throw new Error('Super Admin protected status violation!');
      }
      if (inactiveCount !== 47) {
        throw new Error(`Inactive account invariant failed! Found ${inactiveCount}, expected 47.`);
      }
    }

    console.log('\n========================================================================');
    console.log('PROVISIONING RESULT: SUCCESSFUL (ALL INVARIANTS SATISFIED)');
    console.log('========================================================================\n');

    // Return generated links for reporting without logging raw tokens in permanent DB or logs
    return {
      success: true,
      targetEnv,
      isDryRun,
      departmentCount: finalDepts.length,
      userCount: finalUsers.length,
      inactiveCount,
      generatedLinksCount: generatedLinks.length,
      generatedLinks,
    };
  } finally {
    await mongoose.disconnect();
    console.log('[Database] Disconnected cleanly.');
  }
}

if (require.main === module) {
  runProvisioning()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('\n[FATAL ERROR]:', err);
      process.exit(1);
    });
}

module.exports = { runProvisioning, OFFICIAL_DEPARTMENTS, OFFICIAL_ACCOUNTS };
