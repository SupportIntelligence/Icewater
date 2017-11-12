
rule n3e9_33ebcc66c95ac692
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.33ebcc66c95ac692"
     cluster="n3e9.33ebcc66c95ac692"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious highconfidence"
     md5_hashes="['059abfe2a77f2bdf914f53fe71e754d9','5fbcfd7c1ebbd807d3150685a2f72044','f683982f86bb569288ed7e66182efadf']"

   strings:
      $hex_string = { da035006600651059004700680069006d0056402a00651059004b006c006d006d004e006a006510590042006f0064006d005640200071007f002200730074007 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
