import "hash"

rule n3fe_230b56c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3fe.230b56c9c8000b12"
     cluster="n3fe.230b56c9c8000b12"
     cluster_size="2628 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="browsefox riskware yontoo"
     md5_hashes="['179f4664f532fd9072028fb398472513', '01c17e00363eb8aa2dd63f2feb369b14', '05a5fc36c33cb1b9302cd77e64b447eb']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(342528,1536) == "2e5453368c173633cd45d03de3fae0d4"
}

