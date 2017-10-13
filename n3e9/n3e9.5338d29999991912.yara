import "hash"

rule n3e9_5338d29999991912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.5338d29999991912"
     cluster="n3e9.5338d29999991912"
     cluster_size="194 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['cb46b925512dc402b8b4d17443373715', '6a4c1ed1c19ae46e1346e99c9ba4e674', 'febf31622377968a12d67d905bdbe1a5']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(503808,1024) == "3fe14b266c4bcc97c5475b777c222024"
}

