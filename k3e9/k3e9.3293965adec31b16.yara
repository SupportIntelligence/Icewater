import "hash"

rule k3e9_3293965adec31b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3293965adec31b16"
     cluster="k3e9.3293965adec31b16"
     cluster_size="340 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['d179bba0d1d1780a43623cbfdc725d9d', 'b2142e896689c1c94fd4638e5f4f0834', '3a9ec2cfd91d8e67bf86aadf8b1b46d1']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(15360,256) == "cc66ac3c5629854ed877c268c081b668"
}

