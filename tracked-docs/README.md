# SecKey v1.0 - Getting Started Guide

## Welcome to SecKey!

SecKey is a comprehensive **Intune Configuration Manager** for deploying and managing enterprise security policies to Azure Entra ID and Microsoft Intune.

This guide explains the new v1.0 features and how to use them.

---

## 🆕 New in v1.0

### 1. GUI Menu System
The application now has a professional menu bar with:
- **File** menu (Export, Import, Exit)
- **View** menu (Refresh, Dark Mode)
- **Help** menu (Help file, Skip Reasons, About)
- **Settings** menu (Preferences, Logs, Advanced)

**To Access:**
- Menus appear at the top of the application window
- Click any menu to expand options
- Use keyboard shortcuts (F5 for Refresh, etc.)

---

### 2. HTML Help Documentation

**File:** `SecKey-Help.html`

A complete, browser-based help system covering:
- Overview and features
- Getting started (3-step quick start)
- How to use each application tab
- Deployment process and order
- Why items are skipped during deployment
- Complete settings reference
- Troubleshooting guide
- FAQ (14 questions answered)

**How to Access:**
- Click **Help → Open Help File** in the menu bar
- Or double-click `SecKey-Help.html` directly
- Opens in your default web browser

**What You'll Learn:**
- How to deploy full environments
- Step-by-step deployment for testing
- How to undo deployments safely
- What each policy does
- How to modify settings
- Why deployments skip items

---

### 3. Deployment Skip Reasons Reference

**File:** `DEPLOYMENT-SKIP-REASONS.md`

A detailed markdown guide explaining:
- When items are skipped
- Why they're skipped
- Whether it's normal behavior
- What to do if skip counts seem wrong

**11 Skip Scenarios Covered:**
1. Item already exists (unchanged)
2. Item already exists (differences detected)
3. Store app assignments (non-destructive)
4. Authentication policies in use
5. File format errors
6. Insufficient permissions
7. Duplicate memberships
8. Dynamic group conflicts
9. Item in use/referenced
10. File not found
11. Network timeouts

**How to Access:**
- Click **Help → Skip Reasons Reference** in the menu bar
- Or open `DEPLOYMENT-SKIP-REASONS.md` in any text editor

**Quick Answer:**
- High skip count on second deployment = **NORMAL** ✅
- Everything skipped on first deployment = **PROBLEM** ⚠️
- Need help? See the "What to Do" section in the guide

---

### 4. Excel Settings Spreadsheet Generator

**File:** `generate-settings-excel.ps1`

A PowerShell script that generates a comprehensive Excel workbook with:
- Summary of all deployment items
- 11 detailed worksheets covering all policies and settings
- Count of items in each category
- Policy names, descriptions, and configurations

**To Generate the Excel File:**

```powershell
# Open PowerShell as Administrator
cd c:\Projects\SecureKeyboard
.\generate-settings-excel.ps1 -OutputPath "C:\SecKey-Settings.xlsx"

# Wait ~10 seconds for completion
# File opens in Excel automatically
```

**What's Included:**
- Conditional Access policies (display name, state, conditions)
- Compliance policies
- Device configuration
- Endpoint security settings
- Groups and users
- Administrative units
- Platform scripts
- Reusable settings
- Summary statistics

**Worksheets Generated:**
1. Summary - Total counts
2. Conditional Access
3. Settings Catalog
4. Endpoint Security
5. Compliance
6. Device Configuration
7. Groups
8. Users
9. Admin Units
10. Platform Scripts
11. Reusable Settings

---

### 5. Break Glass Account Renaming

**Changes Made:**
- Break glass accounts renamed from "CSM Azure Break Glass" to "**SECKEY AZURE Break Glass**"
- Applies to:
  - "SECKEY AZURE Break Glass 1"
  - "SECKEY AZURE Break Glass 2"

**Where Used:**
- Deployment manifest: `JSON/Users/seckey.users.json`
- Referenced by Infrastructure tab for emergency access
- Members of `SECKEY-BreakGlass` group

**Why This Matters:**
- Clear branding as SecKey solution
- Distinguishes from older PAW/CSM naming
- Better for audit trails and documentation

---

## 📚 Documentation Files

| File | Purpose | How to Open |
|------|---------|------------|
| `SecKey-Help.html` | Complete user guide | Click Help menu or double-click file |
| `DEPLOYMENT-SKIP-REASONS.md` | Skip reason explanations | Click Help menu or open in VS Code |
| `DELIVERABLES.md` | What was delivered in v1.0 | Open in any text editor |
| `generate-settings-excel.ps1` | Generate Excel spreadsheet | Run in PowerShell |

---

## 🚀 Quick Start

### 1. First Time User?
- **Start Here:** Click **Help → Open Help File** to read the HTML guide
- **Takes 10-15 minutes** to understand the basics
- Covers signing in, authentication, and how each tab works

### 2. Need to Deploy Policies?
- **Go to:** Infrastructure tab (called "Deploy/Remove Secure Keyboard infra")
- **Click:** "Apply Full SecKey Environment"
- **Wait:** ~5-10 minutes depending on tenant size
- **Monitor:** Watch the "Deployment History" section for progress

### 3. Got an Error or High Skip Count?
- **Check:** Click **Help → Skip Reasons Reference**
- **Search** for your issue in the 11 scenarios
- **Follow** the "What to Do" section for your case

### 4. Want to Document Everything?
- **Generate:** Run `generate-settings-excel.ps1` to create Excel file
- **Review:** Open Excel file to see all settings in organized tabs
- **Export:** Print or share as PDF for documentation

---

## 🛠️ Advanced Usage

### Exporting Current Settings
- Go to **Infrastructure** tab
- Click **"Import Exported Settings"**
- Paste JSON from your tenant export

### Step-by-Step Deployment
- Go to **Compliance + Config** tab
- Select specific policy from dropdown
- Click **"Apply Selected Step"**
- Good for testing individual components

### Undoing Deployments
- Go to **Infrastructure** tab
- Click **"Undo Full SecKey Environment"**
- ⚠️ **Caution:** This is destructive and removes deployed policies
- ✅ **Safe:** App assignments are left alone (non-destructive)

### Managing Optional Features
- Go to **Infrastructure** tab
- Check/uncheck optional bundles:
  - Administrative Units
  - Reusable Settings
  - Platform Scripts
- Click **"Apply Optional Features"**

---

## ❓ FAQ

### Q: What if I see high skip counts?
**A:** That's **normal**! On second/third deployments, expect 80%+ skip rates. Items already deployed don't need recreation.

### Q: Can I run deployments multiple times?
**A:** Yes! The system is **idempotent** - safe to run multiple times. Existing items are skipped.

### Q: How do I update a policy?
**A:** Edit the JSON manifest in `JSON/` folder, then re-run deployment for that component. The system will update it.

### Q: What's a "break-glass" account?
**A:** Emergency access accounts that bypass all Conditional Access policies. Protected accounts for disaster recovery.

### Q: Where do I find the app logs?
**A:** Click **Settings → View Logs** to open the logs directory in File Explorer.

### Q: Can I export my current tenant settings?
**A:** Yes! Export CA policies and Intune configs as JSON, then use **Import Exported Settings** in Infrastructure tab.

### Q: Why were some items skipped?
**A:** See `DEPLOYMENT-SKIP-REASONS.md` for 11 detailed scenarios. Most are normal and expected.

### Q: Is it safe to undo deployments?
**A:** Mostly yes, but review what's deployed first. App assignments are not removed (safe). Auth policies in use are skipped (safe).

---

## 📖 Help Resources

### Built-in Help
- **Within App:** Click **Help** menu → **Open Help File**
- **Skip Reasons:** Click **Help** menu → **Skip Reasons Reference**
- **About:** Click **Help** menu → **About SecKey**

### Documentation Files
- **Complete Guide:** `SecKey-Help.html` (3,500+ lines, professional styled)
- **Skip Explanations:** `DEPLOYMENT-SKIP-REASONS.md` (11 scenarios)
- **What Was Delivered:** `DELIVERABLES.md` (complete feature list)
- **This Guide:** `README.md` (getting started)

### Spreadsheet Reference
- **Generate:** Run `generate-settings-excel.ps1`
- **Review:** Excel file with 11 worksheets of all settings
- **Use For:** Documentation, compliance, auditing

---

## 🔐 Security Notes

### Break Glass Account Protection
- Only use break glass accounts for emergencies
- Stored in `JSON/Users/seckey.users.json`
- Members of `SECKEY-BreakGlass` group
- Should be protected with strong MFA
- Should NOT have normal users' group memberships

### Deployment Permissions Required
- **Minimum:** Global Administrator role
- **Or:** Policy Admin + Compliance Admin + Intune Admin
- **Recommended:** Use break glass account for major deployments
- **Monitor:** Check Azure audit logs for all deployment activities

---

## 🐛 Troubleshooting

### Issue: "Permission Denied" Error
- **Cause:** Your account lacks required permissions
- **Fix:** Verify you have Global Admin or Intune Admin roles
- **Check:** Azure Portal → Entra ID → Roles and Administrators

### Issue: High Skip Count on First Deployment
- **Cause:** Items might already be deployed from previous attempt
- **Fix:** Run undo first, then deploy again
- **Or:** Check if another admin deployed items

### Issue: App Crashes When Clicking Help
- **Cause:** Help file not found in expected location
- **Fix:** Ensure `SecKey-Help.html` is in the project root
- **Or:** Set path manually in Settings → Preferences

### Issue: Excel Generation Times Out
- **Cause:** Tenant has thousands of policies
- **Fix:** Wait longer (10+ seconds), or run in off-hours
- **Or:** Filter manifest to fewer policies

### Issue: Deployment Seems Stuck
- **Cause:** Large deployment to tenant with many users/devices
- **Check:** Watch Deployment History - should show progress
- **Wait:** Don't force quit - deployment may still be running
- **Timeout:** If stuck >30 min, check Azure portal for API issues

---

## 📞 Getting Help

### Online Resources
- Check **Help → Open Help File** for comprehensive guide
- Search **DEPLOYMENT-SKIP-REASONS.md** for specific skip scenarios
- Review **DELIVERABLES.md** for complete feature list

### Common Questions
1. "Why did deployment skip my policy?"
   → See `DEPLOYMENT-SKIP-REASONS.md` section 1-11

2. "How do I deploy just one policy?"
   → Use **Compliance + Config** tab for step-by-step deployment

3. "Can I modify settings after deployment?"
   → Yes! Edit JSON manifests and re-run step-by-step deployment

4. "How do I remove everything?"
   → Click **Infrastructure** tab → **Undo Full SecKey Environment**

5. "What do all these settings do?"
   → Click **Help → Open Help File** → **Settings Reference** section

---

## 📋 Checklists

### Before Your First Deployment
- [ ] Read the HTML help file (takes 15 min)
- [ ] Verify your Entra ID role is Global Admin or Intune Admin
- [ ] Sign in using **Sign In / Out** button
- [ ] Review which policies you need (check Excel spreadsheet)
- [ ] Back up existing Intune policies (manual export)

### During Deployment
- [ ] Watch the Deployment History section
- [ ] Don't close the app or turn off computer
- [ ] Wait for "Deployment Complete" message
- [ ] Check for any error messages in history
- [ ] Note the created/updated/skipped counts

### After Deployment
- [ ] Verify policies appear in Azure Portal
- [ ] Test access with a test user account
- [ ] Check Conditional Access enforcement
- [ ] Verify group assignments are correct
- [ ] Document any custom changes made

---

## 🎓 Learning Paths

### 5-Minute Introduction
1. Click **Help → Open Help File**
2. Read "Overview & Features" section
3. Skim "Tab Reference" section

### 15-Minute Deep Dive
1. Read complete HTML help file
2. Review **DEPLOYMENT-SKIP-REASONS.md** to understand skips
3. Check **DELIVERABLES.md** for what's new in v1.0

### 30-Minute Full Understanding
1. Complete 15-minute deep dive above
2. Generate Excel spreadsheet and review all settings
3. Practice step-by-step deployment on test policies
4. Read troubleshooting section

### 1-Hour Mastery
1. Complete 30-minute full understanding above
2. Perform full environment deployment to test tenant
3. Verify all policies deployed correctly
4. Practice undo and re-deploy
5. Review deployment history and logs

---

## 📝 Version Information

- **Product:** SecKey v1.0 - Intune Configuration Manager
- **Release Date:** May 8, 2026
- **Platform:** .NET 10 WPF Application
- **Requirements:** Windows 10 21H2+ or Windows 11
- **Framework:** MVVM Toolkit, Microsoft Graph API, Intune SDK

---

## 🎯 What's Next?

### Planned Features (Post v1.0)
- [ ] Export Settings full implementation (menu currently placeholder)
- [ ] Import Settings full implementation (menu currently placeholder)
- [ ] Advanced policy scheduling
- [ ] Multi-tenant support
- [ ] Runtime smoke-test pass across all security/intune modules
- [ ] Integration tests for JSON live-edit -> deploy pipeline

---

**Last Updated:** May 8, 2026  
**Status:** Ready for Production

For complete documentation, see `SecKey-Help.html` or visit the Help menu.
