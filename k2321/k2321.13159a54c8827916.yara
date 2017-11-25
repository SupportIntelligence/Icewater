
rule k2321_13159a54c8827916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.13159a54c8827916"
     cluster="k2321.13159a54c8827916"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma rontokbro"
     md5_hashes="['2c2b98827f4b90ceb6cc11e5f2da32e6','5a48d94e21ec6569aba8cd7dbc657d98','fe90f6194a2f57b0cbb9e7d9500a404c']"

   strings:
      $hex_string = { dda34677e85b226a74aadb2bb4f5f04cf3f11ddad29e6518d54fafce2636c08b334b0824a00dcbc6acbc5061557a5256f6c27b33eb29ed9dd9c41a786366895a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
