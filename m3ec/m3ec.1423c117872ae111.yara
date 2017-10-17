import "hash"

rule m3ec_1423c117872ae111
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.1423c117872ae111"
     cluster="m3ec.1423c117872ae111"
     cluster_size="460 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['85ac92a38b8611860ffa27beb7a0b9df', 'e8fc7b5f7fdbdd98ef3fc1a435744ebb', '68a42673e349271eeb083dbb6fb0faf5']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(97792,1024) == "7bf7a6f810322ec2626cab82c990beac"
}

