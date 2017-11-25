
rule n3e9_5236ce84c4bbd8b0
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.5236ce84c4bbd8b0"
     cluster="n3e9.5236ce84c4bbd8b0"
     cluster_size="2381"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['001708232bc37c1b19c2b119da88d61b','0050ef739f4ad79f60fce33ecb0aa7fe','032b88acf924f1bbdaff4d73435a88c5']"

   strings:
      $hex_string = { 000102030405060708171e23272b2e313437393c3e40424446484a4c4e505153555658595b5c5e5f616263656667696a6b6c6e6f7071727375767778797a7b7c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
