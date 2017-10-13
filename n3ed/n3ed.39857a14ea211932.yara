import "hash"

rule n3ed_39857a14ea211932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.39857a14ea211932"
     cluster="n3ed.39857a14ea211932"
     cluster_size="30480 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['024fcda7fc3b5ea0c64d732422ecd28d', '011dc12d238305b2b99d6707f6576542', '02820ff3e6aadf22877b0eb58d9e51ef']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(362496,1024) == "2c262d66b505baf68ab3851e94a5ba11"
}

