import "hash"

rule n3e9_319d7ec1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.319d7ec1c4000b12"
     cluster="n3e9.319d7ec1c4000b12"
     cluster_size="635 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="graftor backdoor injector"
     md5_hashes="['1c4f4287cf54a76f4d854475a3e58d85', '2d3c16cc539a3741b37c932d4c7032d6', '63cd9f0dc769390c83583a4d70b2dde9']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(70656,1024) == "c919c220acbc4efea6b47f7e3d8c32b0"
}

