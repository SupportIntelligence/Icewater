import "hash"

rule n3e9_169616c9cc000b54
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.169616c9cc000b54"
     cluster="n3e9.169616c9cc000b54"
     cluster_size="175 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple virut rahack"
     md5_hashes="['4dcc2999ee4597ae1309d3b98e707dbf', 'd0efe5fd5701b16e26101c64edb0ac1b', 'bdf7d0d598abfe6268bb516130868dae']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(248320,1024) == "d8cc9b308b30fba3ddb1b207551904c4"
}

