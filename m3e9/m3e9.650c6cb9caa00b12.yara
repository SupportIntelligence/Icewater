
rule m3e9_650c6cb9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.650c6cb9caa00b12"
     cluster="m3e9.650c6cb9caa00b12"
     cluster_size="37"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys pronny"
     md5_hashes="['00fd4b2cd16292f1f6bf5e8c72881cc3','02fcaf8239ffdce63e3acb0ae8501a34','afb962154a644b953aee47ce543353c0']"

   strings:
      $hex_string = { 20850e01314f50355a8e8e9295a06a6266674e2f53575694ebeeedd38516000000000000000000000000cadaf9f9ff03ffd6ffef9e7a13498a879aadd7f8af39 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
