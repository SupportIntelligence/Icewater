
rule m26c0_350ccfd1c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26c0.350ccfd1c4000b32"
     cluster="m26c0.350ccfd1c4000b32"
     cluster_size="39"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer malicious filerepmalware"
     md5_hashes="['c1790c02ea62e3fe9933df2dadb9ce3ef73a3a2a','7da5e4ae59fd84567d2dcd08a70684cb47820194','7be2e6db8c29cab640953fd66d140623b3ae1189']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26c0.350ccfd1c4000b32"

   strings:
      $hex_string = { be443c0c4f66890683c60285ff7fef5f8bceb8200000002bcdd1f92bc150e89b87000033c06689065e5d83c410c38b44240453ff74240c33db85c00f98c34b23 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
