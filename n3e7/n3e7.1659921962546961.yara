
rule n3e7_1659921962546961
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.1659921962546961"
     cluster="n3e7.1659921962546961"
     cluster_size="14"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler bogqn"
     md5_hashes="['094a57a5e23562b086af68d94e03f4c5','24d506a776edc26f6bacc2b33ac4ea6d','efeeb8bd07a9050e7438938796b4cc8c']"

   strings:
      $hex_string = { 250064002900110049006e00760061006c0069006400200063006f00640065002000700061006700650008004600650062007200750061007200790005004d00 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
