import "hash"

rule m3e9_7396929d9eb75b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.7396929d9eb75b32"
     cluster="m3e9.7396929d9eb75b32"
     cluster_size="18804 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="murofet zbot small"
     md5_hashes="['010d1f088746b81e59304ea468a398c3', '01ad9a5ffc5247449b6c1d8430bb991a', '04428f5d42dbafe4eefac9ffd9ea7dbe']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(19456,1024) == "1bc63b563418ac0acb5d3ad2ea595cae"
}

