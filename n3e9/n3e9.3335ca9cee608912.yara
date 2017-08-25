import "hash"

rule n3e9_3335ca9cee608912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3335ca9cee608912"
     cluster="n3e9.3335ca9cee608912"
     cluster_size="19117 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="downloadguide bundler downloaderguide"
     md5_hashes="['031b16b059eedc96478715cf1cec01da', '035f25463cc28cf3221dd15ec9a7c1e5', '0138f2fe9b04b0a73620223f7c544e05']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(535040,1024) == "54408539baf94b5661e46fba350c1782"
}

