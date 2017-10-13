import "hash"

rule n3e9_469633bda6211932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.469633bda6211932"
     cluster="n3e9.469633bda6211932"
     cluster_size="9464 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['0224ea1fda66ae0d4aefdb54439361c7', '01c7a2ad7d01a69cec503d8f0746dafd', '03f022b2478d5613d656a395ef5df519']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(235520,1024) == "bffec025a956204692284129053ede1c"
}

