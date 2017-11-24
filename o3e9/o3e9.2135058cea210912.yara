
rule o3e9_2135058cea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.2135058cea210912"
     cluster="o3e9.2135058cea210912"
     cluster_size="85"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="weiduan malicious riskware"
     md5_hashes="['021a104070c2259e5db9673ddc0abbfd','0377d8474a3a0af766f4f0ce654690ad','3e104f79bd49bc2ff72fe01211908ddc']"

   strings:
      $hex_string = { 3cbbc01d26e67810b92f143a8811cd4a0e435473337fc6c5e1dcdd89869128388e686272fd39521ace7dbc491ef705be82f9a7a6275f84bdf142871c5881e87b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
