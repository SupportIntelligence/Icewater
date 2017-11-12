
rule k3e9_5f6e16b9aa221132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.5f6e16b9aa221132"
     cluster="k3e9.5f6e16b9aa221132"
     cluster_size="46"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre kryptik trojandownloader"
     md5_hashes="['08265ea58a103dfe2ec8881b16e9c00b','0b266b8593458cdd46051ba88748693e','aa911c60846a75e33566220461ad8826']"

   strings:
      $hex_string = { fffcfdffffcabbf9ff3c2893ff020195ff0a028bff3c2893ffbcbddafff4eff1fffcf9f4fffcfaebfffffbfefff4f8f5fffffbfeff988ebcfffdfefefff9faff }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
