import "hash"

rule n3e9_049d9ac1c4000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.049d9ac1c4000932"
     cluster="n3e9.049d9ac1c4000932"
     cluster_size="9002 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['070a672b5c9e6c84dd135cbf916e5012', '001fcea024e8f74027e27e0cd5cebe55', '0383a77b0182ac01b22ea1a8261e4a90']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(278528,1024) == "49fedfe9d66be3a6026b41fc3b0e9b08"
}

