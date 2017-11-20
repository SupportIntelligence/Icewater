
rule m3e9_3a5fb54bc2200b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a5fb54bc2200b14"
     cluster="m3e9.3a5fb54bc2200b14"
     cluster_size="92"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod wapomi"
     md5_hashes="['2e5d511fd83bfca1509d7641fbda048e','2e75cac90855fb3a3ad84d3d7d293459','a2e209fb8bcbeeeb7de0cc6f4d55ab61']"

   strings:
      $hex_string = { 00f2441e614f3060245b7810208a7602aa65a1573c08b898c866ae878c1afb497479c92ef854b424154c0bef7f1a924ad71872b6c28f4569d8231691068ed16b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
