package main

import (
	"github.com/damianmcgrath/threagile/model"
)

type damiansRiskRule string

// exported as symbol (here simply as variable to interface to bundle many functions under one symbol) named "CustomRiskRule"
var CustomRiskRule damiansRiskRule

func (r damiansRiskRule) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:                         "damian",
		Title:                      "Damians Demo",
		Description:                "Damians Demo Description",
		Impact:                     "Global Catastrophe",
		ASVS:                       "Damians ASVS",
		CheatSheet:                 "https://example.com",
		Action:                     "Damians Demo Action",
		Mitigation:                 "Damians Demo Mitigation",
		Check:                      "Damians Demo Check",
		Function:                   model.Development,
		STRIDE:                     model.Spoofing,
		DetectionLogic:             "Demo Detection",
		RiskAssessment:             "Demo Risk Assessment",
		FalsePositives:             "Demo False Positive.",
		ModelFailurePossibleReason: false,
		CWE:                        0,
	}
}

func (r damiansRiskRule) SupportedTags() []string {
	return []string{"damian"}
}

func (r damiansRiskRule) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, techAsset := range model.ParsedModelRoot.TechnicalAssets {
		if techAsset.IsTaggedWithAny("damian") {
			risks = append(risks, createDamianRisk(techAsset))
		}
	}
	return risks
}

func createDamianRisk(technicalAsset model.TechnicalAsset) model.Risk {
	risk := model.Risk{
		Category:                     CustomRiskRule.Category(),
		Severity:                     model.CalculateSeverity(model.VeryLikely, model.MediumImpact),
		ExploitationLikelihood:       model.VeryLikely,
		ExploitationImpact:           model.VeryHighImpact,
		Title:                        "<b>Damian's demo</b> risk at <b>" + technicalAsset.Title + "</b>",
		MostRelevantTechnicalAssetId: technicalAsset.Id,
		DataBreachProbability:        model.Possible,
		DataBreachTechnicalAssetIDs:  []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
