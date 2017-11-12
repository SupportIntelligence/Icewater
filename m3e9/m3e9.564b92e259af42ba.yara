import "hash"

rule m3e9_564b92e259af42ba
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.564b92e259af42ba"
     cluster="m3e9.564b92e259af42ba"
     cluster_size="322 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['b0da1af965ac6053b8b4ba6e120311cd', 'cf17c3e09e6419cb7eda4645736c2c56', 'd951cfa455afc9b228ac5cd29269e9a0']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(42336,1032) == "9bd0ea6c56ccf5d0f3f10cad88c9b869"
}

