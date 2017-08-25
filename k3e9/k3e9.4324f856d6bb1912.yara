import "hash"

rule k3e9_4324f856d6bb1912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4324f856d6bb1912"
     cluster="k3e9.4324f856d6bb1912"
     cluster_size="21 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b030867428a625a5e3c117806a91a85c', 'a8c58bf7120935fb05870ffb6463b816', 'b5816816c364b6b25e7ad4c1c546602d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20992,256) == "a5658a555b991c738a328ec7df4c12bc"
}

