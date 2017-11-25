
rule k2321_4910dca6dfa31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.4910dca6dfa31932"
     cluster="k2321.4910dca6dfa31932"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hupigon backdoor razy"
     md5_hashes="['0d4867f3ccba0c08221e1d69157a5e2e','4191a61f3f6f22d464b5409fd5c4b6ce','d6411206285a6c3b833d984cba3b184a']"

   strings:
      $hex_string = { 48b330203a92a55d161f98c478889475fadef2628eacdd538974522134615a09e5d72d6914d90e18522be8d8a6a4725c3e32a3a095be8ec6e136bd9a83514a6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
