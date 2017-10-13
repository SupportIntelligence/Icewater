import "hash"

rule m3ed_296fa114b5a16b96
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.296fa114b5a16b96"
     cluster="m3ed.296fa114b5a16b96"
     cluster_size="7 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['6c992c01fc1eb646d5e85948488357d4', 'bbb1f7340e2945613f04e736fd0cb5cd', 'bbb1f7340e2945613f04e736fd0cb5cd']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(91136,1098) == "6328c395671af3d442197f887ae83fcf"
}

