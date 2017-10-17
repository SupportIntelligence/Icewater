import "hash"

rule m3ec_1423c117872b9912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.1423c117872b9912"
     cluster="m3ec.1423c117872b9912"
     cluster_size="48 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['d771454d3b866e92f0cf0e89fbfa0208', '11b14b88c3ae48af9ad65d80fb3b3bd1', '389a5dc396bddf7fed85896d88d06b4e']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(97792,1024) == "7bf7a6f810322ec2626cab82c990beac"
}

