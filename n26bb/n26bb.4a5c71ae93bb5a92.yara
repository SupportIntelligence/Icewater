
rule n26bb_4a5c71ae93bb5a92
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.4a5c71ae93bb5a92"
     cluster="n26bb.4a5c71ae93bb5a92"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="symmi riskware attribute"
     md5_hashes="['4d2f76bdac0f30d4258cf2769674f75ecdc9f0c3','cef725cd831675685b7f903c687aa13d898eb199','d50ca40d64062fe1ca6e9edc3944a4eff50c39e4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.4a5c71ae93bb5a92"

   strings:
      $hex_string = { 7c2366903c397f088a4601463c307df43bf17611e8fb10fcff4883f80f774285ff740289076a036814994a0056e8e5cc030083c40c85c0752d50505033d28d4e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
