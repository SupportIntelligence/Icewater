
rule k3f8_3a2365668dfb5132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f8.3a2365668dfb5132"
     cluster="k3f8.3a2365668dfb5132"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smforw androidos smsspy"
     md5_hashes="['488013191441b922341238983a5e600507e79b85','79f1e5802041d862f0d43017dca5a806cc487c7d','6fd2ecece0badc87bba9bf641d2c9efb3069bdb7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k3f8.3a2365668dfb5132"

   strings:
      $hex_string = { 0873687574646f776e00194c6a6176612f6c616e672f537472696e674275696c6465723b00104572726f7220526573706f6e73653a200006617070656e640015 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
