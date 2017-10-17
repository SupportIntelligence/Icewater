import "hash"

rule m3e9_692f829cda9b1912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.692f829cda9b1912"
     cluster="m3e9.692f829cda9b1912"
     cluster_size="12 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="jadtre qvod viking"
     md5_hashes="['0669ff22aa697aa30de615825c3fe00f', '3f164b161f9542d666606f681b1fe782', 'c76703f9b7348054372e6ff35b5ef4cf']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(57344,1024) == "17bb2f77974ec7dfe7028de9f705c059"
}

