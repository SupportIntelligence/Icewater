import "hash"

rule m3ed_4b958d1f44964692
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.4b958d1f44964692"
     cluster="m3ed.4b958d1f44964692"
     cluster_size="713 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['a52b5355edddf19fe3bf767ccb5cc8ba', 'a264c98991b592d976549c78ecdc7446', '4c8b9b9238780b95423db7534aac2369']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(167936,1033) == "e9430c6b688144805343ddde81304f50"
}

