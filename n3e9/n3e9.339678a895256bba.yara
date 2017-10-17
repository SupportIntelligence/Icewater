import "hash"

rule n3e9_339678a895256bba
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.339678a895256bba"
     cluster="n3e9.339678a895256bba"
     cluster_size="100 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['04f6d2e3889446bc9c24c61cccce352a', 'e79dba908a20e6dce1b0ea8bd0fac755', 'e79dba908a20e6dce1b0ea8bd0fac755']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(129536,1024) == "eba7f5ba913ec5252682e7215221944f"
}

