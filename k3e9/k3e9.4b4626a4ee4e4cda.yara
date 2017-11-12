import "hash"

rule k3e9_4b4626a4ee4e4cda
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4b4626a4ee4e4cda"
     cluster="k3e9.4b4626a4ee4e4cda"
     cluster_size="34 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171031"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['cbb57704ec2e22dfbd3ac83dfbeb8043', 'da61fa6ed830a7de2b501192f9ce592e', 'c1ebfde6e929d4f2e90a154e35cf19cd']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536 and 
      hash.md5(38400,1280) == "8d605714fc674665af1478a4a862ce98"
}

