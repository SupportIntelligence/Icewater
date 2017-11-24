
rule m3e9_64953a99c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.64953a99c2200b32"
     cluster="m3e9.64953a99c2200b32"
     cluster_size="71"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus jorik symmi"
     md5_hashes="['07a1f54bf0a374d4d22de2f799a36823','247069a8d173f192c9321410f381773f','a2f4c4bb014004f9719184c5f245eac7']"

   strings:
      $hex_string = { 83838584c5c3dcf3e1f8f6bd716b634a483f6bbfddf3dcd1c4bfbf755d544f4f0f0ecfe1f9f9f6f6f3cd5e43000000197d8586e3b1dff0f1f8f8f5cfbec071b7 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
