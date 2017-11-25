
rule k3e9_193e79e351b2f316
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.193e79e351b2f316"
     cluster="k3e9.193e79e351b2f316"
     cluster_size="948"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore unwanted buzf"
     md5_hashes="['0016f783c2324f0e54e956e857fff236','004452b847b408b124369c606591687f','036ae899d0d4bb802c5817e2fbf5452f']"

   strings:
      $hex_string = { 7db4c18511a648f025a996078b0ed0aefebf5ce050d898f3e52cdb3f5e335db592ce2e5b678329af3e4e3410451308bdf19e7eadb3a4ecaa361f144dc26f31b8 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
