
rule k3e9_231d17a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.231d17a9c8800b12"
     cluster="k3e9.231d17a9c8800b12"
     cluster_size="4116"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mydoom email malicious"
     md5_hashes="['0029f92fdb9181a7ab8224fc2ba3fd4d','002f4fe003bfaf888026402fd4cdd541','011cf9c881fcf19d9db85d3ed9adf911']"

   strings:
      $hex_string = { 05062fa1ed3682dca92e07de2b585d4eb6e7b3e001e201ec6be4d888d19b1592a80421883c67743f2ac65ea72c38c53a334d0140af9a658850bc4745894bc512 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
