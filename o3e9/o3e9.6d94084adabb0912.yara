
rule o3e9_6d94084adabb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.6d94084adabb0912"
     cluster="o3e9.6d94084adabb0912"
     cluster_size="4582"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="imali crossrider rftt"
     md5_hashes="['0000744c921b1efdefa0334684a21a5d','000a8bb9b51541d53691483fbc74b2e6','00e08a9b517b60e77d6797d63cb46524']"

   strings:
      $hex_string = { 38be537df4d29261c4f6e936796ae9d81636d900f0e74bc8a82dc65a7028009dc077bdf22563617c531f8406de9a505a1727d5d8f4ca1bd8121778b7de5429eb }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
