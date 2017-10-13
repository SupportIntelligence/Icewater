import "hash"

rule n3e9_33339499c2210912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.33339499c2210912"
     cluster="n3e9.33339499c2210912"
     cluster_size="2846 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="downloadguide bundler downloaderguide"
     md5_hashes="['0ad8bd86b1bc31af933cc1269d422dde', '0874296e7bd1339e75fbfb365fb3b52f', '0a0ea064ad90aa8a22be56d3926a07ac']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(510976,1024) == "fa716579da0995e1f72ab2b907b2339d"
}

