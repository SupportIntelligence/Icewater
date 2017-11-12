import "hash"

rule n3e9_319d7ec1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.319d7ec1c4000b12"
     cluster="n3e9.319d7ec1c4000b12"
     cluster_size="6229 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="graftor backdoor injector"
     md5_hashes="['0aa01b23d5cbe196a9d8c620a8deeaf4', '120cb2fde649a309119236d22dde1b50', '1978095e13712b01b75fcb36b0fa2c7e']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(70656,1024) == "c919c220acbc4efea6b47f7e3d8c32b0"
}

