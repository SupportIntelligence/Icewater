import "hash"

rule n3e9_119d2a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.119d2a49c0000b12"
     cluster="n3e9.119d2a49c0000b12"
     cluster_size="865 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['2d01d00345611242fc02a110b926ed69', '88568b3be6e509c24d8a155218d8c75d', '2c30bfc22c2f35a60ac686393516abbd']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(216576,1024) == "6eede9d26636f0fa95fd0363c44a62a7"
}

