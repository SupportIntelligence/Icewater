
rule n231d_09981299c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.09981299c2200b12"
     cluster="n231d.09981299c2200b12"
     cluster_size="100"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos bankbot banker"
     md5_hashes="['3d40b3533f728430f1923a172eea999057cf3af4','d6a81845a9d8ec94cab4fc478e824318d2cac39b','c598094aedfa86370e639325897676d0050a95ad']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.09981299c2200b12"

   strings:
      $hex_string = { e91656a93d3c35c73b2fff0baac10eb4d61833dc37b5af522745a14a967f5dc9d46253cb573f9ef099df702c3e0ffeccfa93693621c084a042b8efcfe1b3bf6b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
