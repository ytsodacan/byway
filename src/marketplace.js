// Pure JSON, no protobuf involved — this is the same logic we already added
// to pserver.py, just moved here so the Worker is the one place it lives now.

export function injectCustomGallery(rawBytes) {
  let data;
  try {
    data = JSON.parse(new TextDecoder().decode(rawBytes));
  } catch (_) {
    return null;
  }
  if (!Array.isArray(data.categories)) return null;
  data.categories.unshift({
    title: "Custom",
    cards: [
      {
        themeCard: {
          campaignId: "custom-1",
          title: "My Custom Sidekick",
          imageUrl: "https://cres.waze.com/private/red.png",
        },
      },
    ],
  });
  return new TextEncoder().encode(JSON.stringify(data));
}

export function customThemeCampaign(campaignId) {
  if (campaignId !== "custom-1") return null;
  return {
    campaign: {
      id: "custom-1",
      name: "My Custom Sidekick",
      title: "My Custom Sidekick",
      subtitle: "A custom drive buddy.",
      description: "A custom sidekick bundle, for testing a private marketplace server.",
      mainImageUrl: "https://cres.waze.com/private/red.png",
      characters: [
        {
          characterId: "custom-char-1",
          characterName: "Custom",
          iconUrl: "https://cres.waze.com/private/red.png",
          voices: [
            {
              voiceId: "16455",
              title: "SpongeBob SquarePants",
              iconUrl: "https://dexter.waze.com/8/6455/Voice/x3.png",
              sampleAssetUrl: "https://dexter.waze.com/8/6455/Voice/voices/StartDrive/1.mp3",
              locale: "en",
            },
          ],
          cars: [
            {
              carId: "16454",
              carName: "Patty Blaster",
              title: "Patty Blaster",
              iconUrl: "https://dexter.waze.com/3/6454/$car.carId/2D/x3.png",
            },
          ],
          moods: [
            {
              moodId: "16453",
              moodName: "MOOD_SPONGEBOB_EN_BRAVE",
              title: "Brave",
              iconUrl: "https://dexter.waze.com/4/6453/$mood.mood_id/x3_ui.png",
            },
          ],
        },
      ],
      shareTitle: "My Custom Sidekick",
      shareBody: "A custom sidekick bundle, for testing a private marketplace server.",
    },
    status: "SUCCESS",
  };
}
