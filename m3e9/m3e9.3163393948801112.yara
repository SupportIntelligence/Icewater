import "hash"

rule m3e9_3163393948801112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3163393948801112"
     cluster="m3e9.3163393948801112"
     cluster_size="10622 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="virut virtob sality"
     md5_hashes="['0336ec5e9ee79f2c7beea40303f979a5', '06d86d12cad6c9a875924914cc87e5aa', '04eb28f397fb5ca02dc9cb29303db0c1']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(41984,1024) == "9e58dde69aa4fa3f18449060b2cb3d17"
}

