
rule n3e9_393173d396566b2e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.393173d396566b2e"
     cluster="n3e9.393173d396566b2e"
     cluster_size="16"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious riskware"
     md5_hashes="['05df5f3ee4f8129955b1b0c8796f5fea','0c111a344353b494cb0a337fe5e2fd99','fc92095df3b16adb24dabe5f1a53c1f1']"

   strings:
      $hex_string = { 6c006f00770020006400750070006c00690063006100740065007300200028002400300025007800290023004100200063006f006d0070006f006e0065006e00 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
