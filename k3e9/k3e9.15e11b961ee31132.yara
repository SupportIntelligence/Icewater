import "hash"

rule k3e9_15e11b961ee31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15e11b961ee31132"
     cluster="k3e9.15e11b961ee31132"
     cluster_size="11 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b1c78135cefed758d89a05b236ceee9a', 'c07d3ef4bbecd7433ae887ad5fd0786a', 'd1ad0954757a5a9e9611ebc795db3602']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(8448,256) == "1e62b5fcfb3e134c6d1424488c1d6c5d"
}

