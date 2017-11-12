import "hash"

rule k3e9_63967b49c8010b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63967b49c8010b16"
     cluster="k3e9.63967b49c8010b16"
     cluster_size="13260 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre ipatre androm"
     md5_hashes="['09c612a4a05ed511ab4f8ac25c7f0237', '05456e213aa863739656405122e7728e', '0cc9c537c2cba3d8f3f04fde25c62571']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4608,1024) == "9d5ca988b8bac62c4c49fb1133d85347"
}

