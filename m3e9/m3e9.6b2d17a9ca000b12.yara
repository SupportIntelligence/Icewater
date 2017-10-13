import "hash"

rule m3e9_6b2d17a9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b2d17a9ca000b12"
     cluster="m3e9.6b2d17a9ca000b12"
     cluster_size="5283 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['0521e38dd7c7d174d838bdc822e2916f', '0ccd58cb85dcacbd32ac1fa321731266', '06a1bf66172ef3de271e8493cdfb1e7c']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(10240,1024) == "d6ce13b328d6c53dfb618f633f2323ac"
}

