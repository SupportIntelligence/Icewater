import "hash"

rule n3e9_469633bda6211932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.469633bda6211932"
     cluster="n3e9.469633bda6211932"
     cluster_size="8502 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['01e81d5af40c9b4af59575a0e569865d', '02e46bdd38b71755b7bb11c5d9e6704e', '00bc46fe5ecad2d17e35ed71e050e580']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(235520,1024) == "bffec025a956204692284129053ede1c"
}

