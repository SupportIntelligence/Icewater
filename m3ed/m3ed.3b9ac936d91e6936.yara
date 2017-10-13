import "hash"

rule m3ed_3b9ac936d91e6936
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.3b9ac936d91e6936"
     cluster="m3ed.3b9ac936d91e6936"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['b7c0d93a57d04cfda053dae4c99b0ce5', 'b7c0d93a57d04cfda053dae4c99b0ce5', 'dc1e63cd04351bca83bf04bb29e0e098']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(73728,1024) == "d8b3e446ad7fc1eeab8a639744aaa5fd"
}

