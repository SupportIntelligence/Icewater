
rule n3e9_4a56ad2cd9ba5315
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4a56ad2cd9ba5315"
     cluster="n3e9.4a56ad2cd9ba5315"
     cluster_size="251"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['00c8d64b12e7a2f4ec0c86c7a9799a38','00d47ccf40664c31e595045ad5cfbc98','1957f45f022c160d8c7abcc1ba524492']"

   strings:
      $hex_string = { cccccc8bff558bec5de97de9ffffcccccccccc8bff558bec5de901eaffffcccccccccc8bff558bec5de934eaffffcccccccccc8bff558bec5de94aeaffffcccc }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
