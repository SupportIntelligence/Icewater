
rule k2321_03959a50c8827916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.03959a50c8827916"
     cluster="k2321.03959a50c8827916"
     cluster_size="8"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma rontokbro"
     md5_hashes="['1d585ad68b98316d4247194c751a8859','2e4b55d21503c61f1882ffebc0e219f9','b8d482a9fd68eadbc8314c4eec774252']"

   strings:
      $hex_string = { dda34677e85b226a74aadb2bb4f5f04cf3f11ddad29e6518d54fafce2636c08b334b0824a00dcbc6acbc5061557a5256f6c27b33eb29ed9dd9c41a786366895a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
