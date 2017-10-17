import "hash"

rule n3e9_1b1d9ec9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1b1d9ec9c4000b32"
     cluster="n3e9.1b1d9ec9c4000b32"
     cluster_size="1275 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="domaiq bundler advml"
     md5_hashes="['8c4af3d5d5413b9a43fd3300b9065f51', '1ebf61d3a5459519b0b80241e3963289', '5ae254d74617be719d797fb8d43e5eea']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(57344,1024) == "17bb2f77974ec7dfe7028de9f705c059"
}

